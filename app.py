import os, csv, re, io, sqlite3, hashlib, hmac, secrets, mimetypes, json
from pathlib import Path
from datetime import datetime, date
from typing import Optional

from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, StreamingResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE / "runtime"))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", DATA_DIR / "uploads"))
DB_PATH = Path(os.environ.get("DATABASE_PATH", DATA_DIR / "high_sky.db"))
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "10"))
PRODUCTION = os.environ.get("APP_ENV") == "production"
SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-only-change-this-secret"
if PRODUCTION and SECRET_KEY == "dev-only-change-this-secret":
    raise RuntimeError("Set SECRET_KEY before starting the production portal")
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".pdf", ".csv", ".tsv", ".xlsx"}
ALLOWED_MIME_PREFIXES = {"image/jpeg", "image/png", "image/webp", "application/pdf", "text/csv", "text/tab-separated-values", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/octet-stream"}
ROLES = ("admin", "operations", "accountant", "driver", "guide", "viewer")
BOOKING_STATUSES = ("Confirmed", "Accepted", "En Route", "Started", "Completed", "Cancelled", "No Show")
EXPENSE_STATUSES = ("Draft", "Submitted", "Approved", "Rejected", "Paid")
EXPENSE_CATEGORIES = ("Fuel", "Parking", "Food", "Entrance Ticket", "Boat Ticket", "Taxi", "Guide Fee", "Driver Fee", "Vehicle", "Other")
DEFAULT_VAT_RATE = 10.0
CHANNEL_TYPES = ("OTA", "Direct", "Website", "Hotel/Agent", "Corporate", "Other")

app = FastAPI(title="High Sky Travels & Tourism Operations Portal", version="5.0")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=os.environ.get("HTTPS_ONLY", "0") == "1")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    return con


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    rounds = 240000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return f"pbkdf2_sha256${rounds}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_hex, digest_hex = encoded.split("$", 3)
        if algo != "pbkdf2_sha256": return False
        test = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)).hex()
        return hmac.compare_digest(test, digest_hex)
    except Exception:
        return False


def ensure_column(con, table: str, column: str, definition: str):
    cols={r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

def get_setting(con, key: str, default=None):
    row=con.execute("SELECT value FROM system_settings WHERE key=?",(key,)).fetchone()
    return row["value"] if row else default

def set_setting(con, key: str, value: str):
    con.execute("INSERT INTO system_settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP",(key,str(value)))

def init_db():
    con = db(); c = con.cursor()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL, phone TEXT, active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS vehicles(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, plate_no TEXT, make_model TEXT,
      seats INTEGER DEFAULT 4, active INTEGER NOT NULL DEFAULT 1, notes TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS bookings(
      id INTEGER PRIMARY KEY AUTOINCREMENT, service_datetime TEXT, purchase_datetime TEXT,
      booking_ref TEXT UNIQUE, supplier_ref TEXT, product TEXT, option_name TEXT, traveler_name TEXT,
      country TEXT, email TEXT, phone TEXT, pax INTEGER DEFAULT 1, price REAL DEFAULT 0,
      net_price REAL DEFAULT 0, currency TEXT DEFAULT 'USD', language TEXT, source TEXT DEFAULT 'GetYourGuide',
      pickup TEXT, notes TEXT, status TEXT DEFAULT 'Confirmed', vehicle_id INTEGER,
      estimated_other_cost REAL DEFAULT 0, cost_currency TEXT DEFAULT 'BHD',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT,
      FOREIGN KEY(vehicle_id) REFERENCES vehicles(id)
    );
    CREATE TABLE IF NOT EXISTS booking_staff(
      id INTEGER PRIMARY KEY AUTOINCREMENT, booking_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      assignment_role TEXT, acceptance_status TEXT DEFAULT 'Pending', response_note TEXT,
      assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, responded_at TEXT,
      UNIQUE(booking_id,user_id), FOREIGN KEY(booking_id) REFERENCES bookings(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS expenses(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, booking_id INTEGER,
      expense_date TEXT NOT NULL, category TEXT NOT NULL, description TEXT, amount REAL NOT NULL,
      currency TEXT DEFAULT 'BHD', receipt_file TEXT, original_filename TEXT, receipt_mime TEXT,
      status TEXT DEFAULT 'Draft', admin_note TEXT, submitted_at TEXT, approved_at TEXT, paid_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(booking_id) REFERENCES bookings(id)
    );
    CREATE TABLE IF NOT EXISTS booking_documents(
      id INTEGER PRIMARY KEY AUTOINCREMENT, booking_id INTEGER NOT NULL, uploaded_by INTEGER NOT NULL,
      document_type TEXT DEFAULT 'Other', stored_filename TEXT NOT NULL, original_filename TEXT NOT NULL,
      mime_type TEXT, file_size INTEGER DEFAULT 0, note TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(booking_id) REFERENCES bookings(id) ON DELETE CASCADE,
      FOREIGN KEY(uploaded_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS incidents(
      id INTEGER PRIMARY KEY AUTOINCREMENT, booking_id INTEGER, user_id INTEGER, title TEXT NOT NULL,
      description TEXT, severity TEXT DEFAULT 'Low', status TEXT DEFAULT 'Open',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(booking_id) REFERENCES bookings(id), FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS audit_log(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL, entity TEXT NOT NULL,
      entity_id INTEGER, detail TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS payment_batches(
      id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL DEFAULT 'GetYourGuide',
      period_start TEXT NOT NULL, period_end TEXT NOT NULL, statement_date TEXT,
      currency TEXT DEFAULT 'USD', stored_filename TEXT NOT NULL, original_filename TEXT NOT NULL,
      mime_type TEXT, file_size INTEGER DEFAULT 0, uploaded_by INTEGER NOT NULL,
      parsed_count INTEGER DEFAULT 0, expected_count INTEGER DEFAULT 0,
      expected_total REAL DEFAULT 0, paid_total REAL DEFAULT 0, variance_total REAL DEFAULT 0,
      status TEXT DEFAULT 'Reconciled', notes TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(uploaded_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS payment_lines(
      id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id INTEGER NOT NULL, booking_ref TEXT,
      booking_id INTEGER, paid_amount REAL DEFAULT 0, expected_amount REAL DEFAULT 0,
      currency TEXT DEFAULT 'USD', variance REAL DEFAULT 0, reconciliation_status TEXT NOT NULL,
      raw_text TEXT, occurrence_no INTEGER DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(batch_id) REFERENCES payment_batches(id) ON DELETE CASCADE,
      FOREIGN KEY(booking_id) REFERENCES bookings(id)
    );
    CREATE TABLE IF NOT EXISTS sales_channels(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, code TEXT UNIQUE,
      channel_type TEXT NOT NULL DEFAULT 'OTA', default_commission_rate REAL DEFAULT 0,
      vat_rate REAL NOT NULL DEFAULT 10, vat_inclusive INTEGER NOT NULL DEFAULT 1,
      active INTEGER NOT NULL DEFAULT 1, notes TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS booking_finance(
      id INTEGER PRIMARY KEY AUTOINCREMENT, booking_id INTEGER UNIQUE NOT NULL, channel_id INTEGER,
      retail_amount REAL DEFAULT 0, currency TEXT DEFAULT 'USD', sales_vat_rate REAL DEFAULT 10,
      sales_vat_amount REAL DEFAULT 0, revenue_ex_vat REAL DEFAULT 0, commission_rate REAL DEFAULT 0,
      commission_amount REAL DEFAULT 0, commission_vat REAL DEFAULT 0, manual_adjustments REAL DEFAULT 0,
      expected_payout REAL DEFAULT 0, actual_payout REAL DEFAULT 0, receivable_balance REAL DEFAULT 0,
      payment_status TEXT DEFAULT 'Unpaid', last_payment_batch_id INTEGER, updated_at TEXT,
      FOREIGN KEY(booking_id) REFERENCES bookings(id) ON DELETE CASCADE,
      FOREIGN KEY(channel_id) REFERENCES sales_channels(id),
      FOREIGN KEY(last_payment_batch_id) REFERENCES payment_batches(id)
    );
    CREATE TABLE IF NOT EXISTS system_settings(
      key TEXT PRIMARY KEY, value TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    ''')
    ensure_column(con,"bookings","archived","INTEGER NOT NULL DEFAULT 0")
    ensure_column(con,"expenses","archived","INTEGER NOT NULL DEFAULT 0")
    ensure_column(con,"booking_documents","archived","INTEGER NOT NULL DEFAULT 0")
    ensure_column(con,"payment_batches","archived","INTEGER NOT NULL DEFAULT 0")
    ensure_column(con,"users","updated_at","TEXT")
    ensure_column(con,"vehicles","updated_at","TEXT")
    ensure_column(con,"sales_channels","updated_at","TEXT")
    if not c.execute("SELECT 1 FROM system_settings WHERE key='default_vat_rate'").fetchone():
        set_setting(con,'default_vat_rate','10')
    if not c.execute("SELECT 1 FROM system_settings WHERE key='company_name'").fetchone():
        set_setting(con,'company_name','High Sky Travels & Tourism')
    if not c.execute("SELECT 1 FROM system_settings WHERE key='company_phone'").fetchone():
        set_setting(con,'company_phone','+973 35623237')
    if not c.execute("SELECT 1 FROM system_settings WHERE key='company_email'").fetchone():
        set_setting(con,'company_email','info@highskytravelsbh.com')
    if c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] == 0:
        admin_password = os.environ.get("ADMIN_PASSWORD", "")
        if len(admin_password) < 12:
            raise RuntimeError("Set ADMIN_PASSWORD to at least 12 characters for first deployment")
        demo = [("High Sky Admin", os.environ.get("ADMIN_EMAIL", "admin@highsky.local"), admin_password, "admin", "+973 35623237")]
        if not PRODUCTION:
            for label, role in [("Operations User", "operations"), ("Accounts User", "accountant"), ("Demo Driver", "driver"), ("Demo Guide", "guide")]:
                password = os.environ.get(role.upper() + "_PASSWORD")
                if password:
                    email = "accounts@highsky.local" if role == "accountant" else role + "@highsky.local"
                    demo.append((label, email, password, role, ""))
        for name,email,pw,role,phone in demo:
            c.execute("INSERT INTO users(name,email,password_hash,role,phone) VALUES(?,?,?,?,?)",(name,email,hash_password(pw),role,phone))
    if c.execute("SELECT COUNT(*) n FROM vehicles").fetchone()["n"] == 0:
        c.executemany("INSERT INTO vehicles(name,plate_no,make_model,seats,notes) VALUES(?,?,?,?,?)",[
          ("High Sky SUV 1","HS-001","Toyota Fortuner",5,"Primary Bahrain private tour vehicle"),
          ("High Sky SUV 2","HS-002","SUV",5,"Backup vehicle")])
    if c.execute("SELECT COUNT(*) n FROM sales_channels").fetchone()["n"] == 0:
        c.executemany("INSERT INTO sales_channels(name,code,channel_type,default_commission_rate,vat_rate,vat_inclusive,notes) VALUES(?,?,?,?,?,?,?)",[
          ("GetYourGuide","GYG","OTA",30.0,10.0,1,"30% is seeded from the supplied payout example and can be edited."),
          ("Viator","VIATOR","OTA",0.0,10.0,1,"Enter your contracted commission rate in Channels."),
          ("Klook","KLOOK","OTA",0.0,10.0,1,"Enter your contracted commission rate in Channels."),
          ("Direct Booking","DIRECT","Direct",0.0,10.0,1,"Cash, card, bank transfer or WhatsApp direct booking."),
          ("Website","WEB","Website",0.0,10.0,1,"Bookings from your own website."),
          ("Hotel / Agent","AGENT","Hotel/Agent",0.0,10.0,1,"Hotel desk, travel agent or concierge booking."),
          ("Corporate","CORP","Corporate",0.0,10.0,1,"Company or group account booking."),
          ("Other","OTHER","Other",0.0,10.0,1,"Custom source.")])
    con.commit(); con.close()


def parse_money(v):
    if v is None: return 0.0, "USD"
    m = re.search(r"(-?[\d,.]+)\s*([A-Z]{3})?", str(v))
    if not m: return 0.0, "USD"
    return float(m.group(1).replace(",", "")), (m.group(2) or "USD")


def parse_dt(v):
    if not v: return None
    for fmt in ("%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M"):
        try: return datetime.strptime(v.strip(), fmt).strftime("%Y-%m-%d %H:%M")
        except ValueError: pass
    return v.strip()


def vat_breakdown(gross: float, rate: float=DEFAULT_VAT_RATE, inclusive: bool=True):
    gross=float(gross or 0); rate=float(rate or 0)
    if rate<=0: return round(gross,3),0.0
    if inclusive:
        vat=gross*rate/(100.0+rate); ex=gross-vat
    else:
        ex=gross; vat=gross*rate/100.0
    return round(ex,3),round(vat,3)


def ensure_booking_finance(con, booking_id:int):
    existing=con.execute("SELECT * FROM booking_finance WHERE booking_id=?",(booking_id,)).fetchone()
    if existing: return existing
    b=con.execute("SELECT * FROM bookings WHERE id=?",(booking_id,)).fetchone()
    if not b: return None
    ch=con.execute("SELECT * FROM sales_channels WHERE lower(name)=lower(?)",(b["source"] or "Other",)).fetchone()
    if not ch:
        ch=con.execute("SELECT * FROM sales_channels WHERE name='Other'").fetchone()
    retail=float(b["price"] or 0); expected=float(b["net_price"] or retail)
    rate=float(ch["vat_rate"] if ch else DEFAULT_VAT_RATE); inclusive=bool(ch["vat_inclusive"] if ch else 1)
    exvat,vat=vat_breakdown(retail,rate,inclusive)
    commission=max(0.0,round(retail-expected,3)) if (b["source"] or "").lower() not in ("direct","direct booking","website") else 0.0
    comm_rate=round(commission/retail*100,4) if retail else 0.0
    con.execute("""INSERT OR IGNORE INTO booking_finance(booking_id,channel_id,retail_amount,currency,sales_vat_rate,sales_vat_amount,revenue_ex_vat,commission_rate,commission_amount,expected_payout,receivable_balance,payment_status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)""",
      (booking_id,ch["id"] if ch else None,retail,b["currency"] or "USD",rate,vat,exvat,comm_rate,commission,expected,expected,"Unpaid"))
    return con.execute("SELECT * FROM booking_finance WHERE booking_id=?",(booking_id,)).fetchone()


def initialize_finance_rows():
    con=db()
    for r in con.execute("SELECT id FROM bookings").fetchall(): ensure_booking_finance(con,r["id"])
    con.commit(); con.close()


def import_seed_bookings():
    if PRODUCTION: return 0
    path = BASE / "data" / "getyourguide_bookings.tsv"
    if not path.exists(): return 0
    con = db()
    if con.execute("SELECT COUNT(*) n FROM bookings").fetchone()["n"] > 0:
        con.close(); return 0
    count = 0
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for r in reader:
            ref = (r.get("Booking Ref #") or "").strip()
            if not ref: continue
            first = (r.get("Traveler's First Name") or "").strip()
            last = (r.get("Traveler's Last Name") or "").strip()
            traveler = " ".join(x for x in (first,last) if x).strip()
            pax = 0
            for key in ("Adult","Senior","Student (with ID)","EU Citizens (with ID)","Student EU Citizens (with ID)","Military (with ID)","Youth","Child","Infant"):
                try: pax += int(float(r.get(key) or 0))
                except: pass
            price, currency = parse_money(r.get("Price"))
            net, net_currency = parse_money(r.get("Net Price"))
            con.execute('''INSERT OR IGNORE INTO bookings(service_datetime,purchase_datetime,booking_ref,supplier_ref,product,option_name,traveler_name,country,email,phone,pax,price,net_price,currency,language,source,notes)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(
              parse_dt(r.get("Date")), parse_dt(r.get("Purchase Date (local time)")), ref,
              (r.get("Supplier Ref #") or "").strip(), (r.get("Product") or "").strip(), (r.get("Option") or "").strip(), traveler,
              (r.get("Traveler's Country") or "").strip(), (r.get("Email") or "").strip(), (r.get("Phone") or "").strip(),
              pax or 1, price, net, net_currency or currency, (r.get("Language") or "English").strip(), "GetYourGuide",
              (r.get("Additional Information") or "").strip()))
            count += 1
    con.commit(); con.close(); return count


def audit(request: Request, action, entity, entity_id=None, detail=""):
    con=db(); con.execute("INSERT INTO audit_log(user_id,action,entity,entity_id,detail) VALUES(?,?,?,?,?)",
                          (request.session.get("user_id"),action,entity,entity_id,detail)); con.commit(); con.close()


def flash(request: Request, message: str, category: str="info"):
    request.session.setdefault("flashes", []).append((category, message))


def ctx(request: Request, **kw):
    flashes = request.session.pop("flashes", [])
    base = dict(request=request, session_user=request.session, flashes=flashes, booking_statuses=BOOKING_STATUSES,
                expense_categories=EXPENSE_CATEGORIES, roles=ROLES, today=date.today().isoformat(), default_vat_rate=DEFAULT_VAT_RATE, channel_types=CHANNEL_TYPES)
    base.update(kw); return base


def require_login(request: Request):
    if not request.session.get("user_id"):
        return RedirectResponse("/login", status_code=303)
    return None


def require_role(request: Request, *allowed):
    x=require_login(request)
    if x: return x
    if request.session.get("role") not in allowed:
        flash(request,"You do not have permission for that page.","danger")
        return RedirectResponse("/", status_code=303)
    return None


def staff_can_access_booking(con, request: Request, bid: int):
    if request.session.get("role") not in ("driver","guide"): return True
    return con.execute("SELECT 1 FROM booking_staff WHERE booking_id=? AND user_id=?",(bid,request.session["user_id"])).fetchone() is not None


def safe_upload_name(original: str) -> str:
    ext = Path(original).suffix.lower()
    return f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(8)}{ext}"


async def save_upload(file: UploadFile, prefix: str="doc"):
    if not file or not file.filename: return None
    original = Path(file.filename).name
    ext = Path(original).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, "File type not allowed. Use JPG, JPEG, PNG, WEBP or PDF.")
    content = await file.read(MAX_UPLOAD_MB * 1024 * 1024 + 1)
    if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"File is larger than {MAX_UPLOAD_MB} MB.")
    mime = file.content_type or mimetypes.guess_type(original)[0] or "application/octet-stream"
    if mime not in ALLOWED_MIME_PREFIXES:
        raise HTTPException(400, "File content type is not allowed.")
    stored = f"{prefix}_{safe_upload_name(original)}"
    target = UPLOAD_DIR / stored
    with open(target, "wb") as out: out.write(content)
    if not target.exists() or target.stat().st_size != len(content):
        raise HTTPException(500, "Upload could not be saved correctly.")
    return {"stored": stored, "original": original, "mime": mime, "size": len(content)}




def normalize_header(v: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (v or "").lower()).strip()


def find_header(headers, keywords):
    normalized = {h: normalize_header(str(h)) for h in headers if h is not None}
    for h,n in normalized.items():
        if all(k in n for k in keywords):
            return h
    return None


def parse_amount_value(v):
    if v is None: return 0.0
    if isinstance(v,(int,float)): return float(v)
    txt=str(v).strip().replace(",","")
    txt=re.sub(r"[^0-9.()\-]", "", txt)
    if txt.startswith("(") and txt.endswith(")"):
        txt="-"+txt[1:-1]
    try: return float(txt or 0)
    except: return 0.0


def extract_payment_rows_from_delimited(content: bytes, delimiter=None):
    text=content.decode("utf-8-sig", errors="replace")
    sample=text[:5000]
    if delimiter is None:
        try: delimiter=csv.Sniffer().sniff(sample, delimiters=",;\t").delimiter
        except: delimiter="," if "," in sample else "\t"
    reader=csv.DictReader(io.StringIO(text), delimiter=delimiter)
    headers=reader.fieldnames or []
    ref_col=(find_header(headers,["booking","ref"]) or find_header(headers,["booking","reference"]) or
             find_header(headers,["reservation","ref"]) or find_header(headers,["reference"]))
    amount_col=(find_header(headers,["retail","price","minus","commission"]) or find_header(headers,["net","price"]) or find_header(headers,["net","amount"]) or
                find_header(headers,["payout"]) or find_header(headers,["payment","amount"]) or
                find_header(headers,["paid","amount"]) or find_header(headers,["amount"]))
    retail_col=find_header(headers,["retail","price"])
    commission_col=find_header(headers,["commission","amount"]) or find_header(headers,["commission"])
    adjustment_col=find_header(headers,["manual","adjustments"]) or find_header(headers,["adjustment"])
    service_vat_col=find_header(headers,["vat","services"]) or find_header(headers,["vat","service"])
    currency_col=find_header(headers,["currency"])
    if not ref_col or not amount_col:
        raise ValueError("Could not identify booking reference and payment amount columns in the file.")
    rows=[]
    for r in reader:
        ref=str(r.get(ref_col) or "").strip()
        if not ref: continue
        rows.append({
          "booking_ref":ref,"paid_amount":parse_amount_value(r.get(amount_col)),
          "retail_amount":parse_amount_value(r.get(retail_col)) if retail_col else None,
          "commission_amount":parse_amount_value(r.get(commission_col)) if commission_col else None,
          "manual_adjustments":parse_amount_value(r.get(adjustment_col)) if adjustment_col else None,
          "commission_vat":parse_amount_value(r.get(service_vat_col)) if service_vat_col else None,
          "currency":str(r.get(currency_col) or "").strip().upper() if currency_col else "",
          "raw_text":json.dumps(r,ensure_ascii=False)[:4000]})
    return rows


def extract_payment_rows_from_xlsx(content: bytes):
    try:
        from openpyxl import load_workbook
    except ImportError as e:
        raise ValueError("Excel support is not installed. Run the requirements installer first.") from e
    wb=load_workbook(io.BytesIO(content), read_only=True, data_only=True)
    ws=wb.active
    data=list(ws.iter_rows(values_only=True))
    if not data: return []
    headers=[str(x or "") for x in data[0]]
    ref_col=(find_header(headers,["booking","ref"]) or find_header(headers,["booking","reference"]) or find_header(headers,["reference"]))
    amount_col=(find_header(headers,["retail","price","minus","commission"]) or find_header(headers,["net","price"]) or find_header(headers,["net","amount"]) or find_header(headers,["payout"]) or find_header(headers,["payment","amount"]) or find_header(headers,["paid","amount"]) or find_header(headers,["amount"]))
    retail_col=find_header(headers,["retail","price"]); commission_col=find_header(headers,["commission","amount"]) or find_header(headers,["commission"])
    adjustment_col=find_header(headers,["manual","adjustments"]) or find_header(headers,["adjustment"]); service_vat_col=find_header(headers,["vat","services"]) or find_header(headers,["vat","service"])
    currency_col=find_header(headers,["currency"])
    if not ref_col or not amount_col: raise ValueError("Could not identify booking reference and payment amount columns in the Excel file.")
    ri=headers.index(ref_col); ai=headers.index(amount_col); ci=headers.index(currency_col) if currency_col else None
    rti=headers.index(retail_col) if retail_col else None; cmi=headers.index(commission_col) if commission_col else None
    adi=headers.index(adjustment_col) if adjustment_col else None; svi=headers.index(service_vat_col) if service_vat_col else None
    out=[]
    for vals in data[1:]:
        ref=str(vals[ri] or "").strip() if ri<len(vals) else ""
        if not ref: continue
        amount=parse_amount_value(vals[ai] if ai<len(vals) else 0)
        curr=str(vals[ci] or "").strip().upper() if ci is not None and ci<len(vals) else ""
        get=lambda idx: parse_amount_value(vals[idx] if idx is not None and idx<len(vals) else 0) if idx is not None else None
        out.append({"booking_ref":ref,"paid_amount":amount,"retail_amount":get(rti),"commission_amount":get(cmi),"manual_adjustments":get(adi),"commission_vat":get(svi),"currency":curr,"raw_text":" | ".join(str(v or "") for v in vals)[:4000]})
    return out


def extract_payment_rows_from_pdf(content: bytes):
    try:
        from pypdf import PdfReader
    except ImportError as e:
        raise ValueError("PDF statement support is not installed. Run the requirements installer first.") from e
    reader=PdfReader(io.BytesIO(content))
    text="\n".join((p.extract_text() or "") for p in reader.pages)
    refs=list(re.finditer(r"\bGYG[A-Z0-9]{6,}\b", text, re.I))
    rows=[]
    for i,m in enumerate(refs):
        start=m.end(); end=refs[i+1].start() if i+1<len(refs) else min(len(text), start+500)
        chunk=text[start:end]
        nums=re.findall(r"(?<![A-Za-z0-9])(-?\d{1,6}(?:,\d{3})*(?:\.\d{1,3})?)\s*(USD|BHD|EUR|GBP)?", chunk, re.I)
        if not nums: continue
        candidates=[]
        for num,curr in nums:
            val=parse_amount_value(num)
            if abs(val)<100000: candidates.append((val,(curr or "").upper()))
        if not candidates: continue
        val,curr=candidates[-1]
        rows.append({"booking_ref":m.group(0).upper(),"paid_amount":val,"currency":curr,"raw_text":chunk[:1000]})
    if not rows:
        raise ValueError("No booking references with payment amounts could be read from this PDF. If the PDF is scanned, export the payout details as CSV or Excel and upload that file instead.")
    return rows


def parse_payment_statement(filename: str, content: bytes):
    ext=Path(filename).suffix.lower()
    if ext==".csv": return extract_payment_rows_from_delimited(content, None)
    if ext==".tsv": return extract_payment_rows_from_delimited(content, "\t")
    if ext==".xlsx": return extract_payment_rows_from_xlsx(content)
    if ext==".pdf": return extract_payment_rows_from_pdf(content)
    raise ValueError("Payment statements must be PDF, CSV, TSV or XLSX.")


def reconcile_payment_batch(con, batch_id:int, source:str, period_start:str, period_end:str, default_currency:str, parsed_rows):
    con.execute("DELETE FROM payment_lines WHERE batch_id=?",(batch_id,))
    counts={}
    paid_total=0.0
    matched_refs=set()
    for row in parsed_rows:
        ref=(row.get("booking_ref") or "").strip().upper()
        if not ref: continue
        counts[ref]=counts.get(ref,0)+1
        occ=counts[ref]
        paid=float(row.get("paid_amount") or 0)
        currency=(row.get("currency") or default_currency or "USD").upper()
        paid_total+=paid
        b=con.execute("SELECT * FROM bookings WHERE upper(booking_ref)=?",(ref,)).fetchone()
        if not b:
            status="Unknown Booking"; expected=0.0; variance=paid; bid=None
        else:
            bid=b["id"]; finance=ensure_booking_finance(con,bid); expected=float(finance["expected_payout"] if finance else (b["net_price"] or 0)); matched_refs.add(ref)
            if (b["currency"] or default_currency).upper()!=currency:
                status="Currency Mismatch"; variance=paid-expected
            elif occ>1:
                status="Duplicate Reference"; variance=paid-expected
            else:
                variance=round(paid-expected,3)
                if abs(variance)<=0.01: status="Exact Match"
                elif variance<0: status="Short Paid"
                else: status="Overpaid"
            if occ==1 and finance:
                retail=row.get("retail_amount"); comm=row.get("commission_amount"); adj=row.get("manual_adjustments"); cvat=row.get("commission_vat")
                if retail is not None:
                    exvat,svat=vat_breakdown(float(retail),float(finance["sales_vat_rate"] or DEFAULT_VAT_RATE),True)
                    con.execute("UPDATE booking_finance SET retail_amount=?,sales_vat_amount=?,revenue_ex_vat=? WHERE booking_id=?",(float(retail),svat,exvat,bid))
                    con.execute("UPDATE bookings SET price=? WHERE id=?",(float(retail),bid))
                updates=[]; vals=[]
                if comm is not None: updates.append("commission_amount=?"); vals.append(abs(float(comm)))
                if adj is not None: updates.append("manual_adjustments=?"); vals.append(float(adj))
                if cvat is not None: updates.append("commission_vat=?"); vals.append(abs(float(cvat)))
                updates += ["actual_payout=?","receivable_balance=?","payment_status=?","last_payment_batch_id=?","updated_at=CURRENT_TIMESTAMP"]
                vals += [paid,round(expected-paid,3),"Paid" if abs(paid-expected)<=0.01 else ("Partially Paid" if paid>0 else "Unpaid"),batch_id]
                vals.append(bid)
                con.execute("UPDATE booking_finance SET "+",".join(updates)+" WHERE booking_id=?",vals)
        con.execute("""INSERT INTO payment_lines(batch_id,booking_ref,booking_id,paid_amount,expected_amount,currency,variance,reconciliation_status,raw_text,occurrence_no)
                     VALUES(?,?,?,?,?,?,?,?,?,?)""",(batch_id,ref,bid,paid,expected,currency,variance,status,row.get("raw_text",""),occ))
    expected_rows=con.execute("""SELECT * FROM bookings WHERE source=? AND date(service_datetime)>=date(?) AND date(service_datetime)<=date(?) ORDER BY service_datetime""",(source,period_start,period_end)).fetchall()
    expected_total=0.0
    for b in expected_rows:
        finance=ensure_booking_finance(con,b["id"]); expected=float(finance["expected_payout"] if finance else (b["net_price"] or 0))
        expected_total+=expected
        ref=(b["booking_ref"] or "").upper()
        if ref and ref not in matched_refs:
            con.execute("""INSERT INTO payment_lines(batch_id,booking_ref,booking_id,paid_amount,expected_amount,currency,variance,reconciliation_status,raw_text,occurrence_no)
                         VALUES(?,?,?,?,?,?,?,?,?,1)""",(batch_id,ref,b["id"],0,expected,(b["currency"] or default_currency).upper(),-expected,"Missing from Statement",""))
    variance=round(paid_total-expected_total,3)
    issue_count=con.execute("SELECT COUNT(*) n FROM payment_lines WHERE batch_id=? AND reconciliation_status!='Exact Match'",(batch_id,)).fetchone()["n"]
    status="Balanced" if issue_count==0 and abs(variance)<=0.01 else "Needs Review"
    con.execute("UPDATE payment_batches SET parsed_count=?,expected_count=?,expected_total=?,paid_total=?,variance_total=?,status=? WHERE id=?",(len(parsed_rows),len(expected_rows),expected_total,paid_total,variance,status,batch_id))
    return {"expected_count":len(expected_rows),"expected_total":expected_total,"paid_total":paid_total,"variance":variance,"status":status,"issues":issue_count}

@app.on_event("startup")
def startup():
    init_db(); import_seed_bookings(); initialize_finance_rows()


@app.get("/health", response_class=PlainTextResponse)
def health():
    try:
        con=db(); con.execute("SELECT 1").fetchone(); con.close()
        test = UPLOAD_DIR / ".write_test"
        test.write_text("ok", encoding="utf-8"); test.unlink()
        return "OK database=ok uploads=ok"
    except Exception as e:
        raise HTTPException(503, f"Health check failed: {e}")


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", ctx(request))

@app.post("/login")
def login_post(request: Request, email: str=Form(...), password: str=Form(...)):
    con=db(); u=con.execute("SELECT * FROM users WHERE lower(email)=? AND active=1",(email.strip().lower(),)).fetchone(); con.close()
    if u and verify_password(password,u["password_hash"]):
        request.session.clear(); request.session.update(user_id=u["id"],name=u["name"],role=u["role"])
        audit(request,"LOGIN","user",u["id"])
        return RedirectResponse("/",status_code=303)
    flash(request,"Invalid login details.","danger"); return RedirectResponse("/login",status_code=303)

@app.get("/logout")
def logout(request: Request):
    request.session.clear(); return RedirectResponse("/login",status_code=303)

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    x=require_login(request)
    if x: return x
    con=db(); role=request.session["role"]; uid=request.session["user_id"]
    if role in ("driver","guide"):
        upcoming=con.execute('''SELECT b.*,v.name vehicle_name,bs.acceptance_status FROM bookings b JOIN booking_staff bs ON bs.booking_id=b.id LEFT JOIN vehicles v ON v.id=b.vehicle_id WHERE bs.user_id=? AND datetime(b.service_datetime)>=datetime('now','-1 day') ORDER BY b.service_datetime LIMIT 12''',(uid,)).fetchall()
        stats={"assigned":con.execute("SELECT COUNT(*) n FROM booking_staff WHERE user_id=?",(uid,)).fetchone()["n"],"pending_acceptance":con.execute("SELECT COUNT(*) n FROM booking_staff WHERE user_id=? AND acceptance_status='Pending'",(uid,)).fetchone()["n"],"pending_expenses":con.execute("SELECT COALESCE(SUM(amount),0) n FROM expenses WHERE user_id=? AND status IN ('Submitted','Approved')",(uid,)).fetchone()["n"],"paid_expenses":con.execute("SELECT COALESCE(SUM(amount),0) n FROM expenses WHERE user_id=? AND status='Paid'",(uid,)).fetchone()["n"]}
    else:
        upcoming=con.execute('''SELECT b.*,v.name vehicle_name,GROUP_CONCAT(u.name, ', ') assigned_names FROM bookings b LEFT JOIN vehicles v ON v.id=b.vehicle_id LEFT JOIN booking_staff bs ON bs.booking_id=b.id LEFT JOIN users u ON u.id=bs.user_id WHERE b.archived=0 AND datetime(b.service_datetime)>=datetime('now','-1 day') GROUP BY b.id ORDER BY b.service_datetime LIMIT 12''').fetchall()
        stats={"bookings":con.execute("SELECT COUNT(*) n FROM bookings WHERE archived=0").fetchone()["n"],"upcoming":con.execute("SELECT COUNT(*) n FROM bookings WHERE archived=0 AND datetime(service_datetime)>=datetime('now')").fetchone()["n"],"revenue":con.execute("SELECT COALESCE(SUM(net_price),0) n FROM bookings").fetchone()["n"],"pending_expenses":con.execute("SELECT COALESCE(SUM(amount),0) n FROM expenses WHERE status IN ('Submitted','Approved')").fetchone()["n"],"unassigned":con.execute("SELECT COUNT(*) n FROM bookings b WHERE NOT EXISTS (SELECT 1 FROM booking_staff bs WHERE bs.booking_id=b.id)").fetchone()["n"]}
    con.close(); return templates.TemplateResponse("dashboard.html",ctx(request,upcoming=upcoming,stats=stats))

@app.get("/bookings", response_class=HTMLResponse)
def bookings(request: Request, q: str=""):
    x=require_login(request)
    if x:return x
    con=db(); role=request.session["role"]
    base='''SELECT b.*,v.name vehicle_name,GROUP_CONCAT(u.name, ', ') assigned_names FROM bookings b LEFT JOIN vehicles v ON v.id=b.vehicle_id LEFT JOIN booking_staff bs ON bs.booking_id=b.id LEFT JOIN users u ON u.id=bs.user_id'''
    params=[]; where=['b.archived=0']
    if role in ("driver","guide"):
        where.append("EXISTS(SELECT 1 FROM booking_staff x WHERE x.booking_id=b.id AND x.user_id=?)"); params.append(request.session["user_id"])
    if q:
        where.append("(b.booking_ref LIKE ? OR b.traveler_name LIKE ? OR b.product LIKE ?)"); params += [f"%{q}%"]*3
    if where: base += " WHERE " + " AND ".join(where)
    base += " GROUP BY b.id ORDER BY b.service_datetime DESC LIMIT 500"
    rows=con.execute(base,params).fetchall(); channels=con.execute("SELECT * FROM sales_channels WHERE active=1 ORDER BY name").fetchall(); con.close()
    return templates.TemplateResponse("bookings.html",ctx(request,rows=rows,q=q,channels=channels))

@app.post("/bookings/new")
def booking_create(request:Request, service_datetime:str=Form(...), booking_ref:str=Form(...), source:str=Form(...), traveler_name:str=Form(...), product:str=Form(...), option_name:str=Form(""), pax:int=Form(1), currency:str=Form("BHD"), retail_amount:float=Form(...), email:str=Form(""), phone:str=Form(""), pickup:str=Form(""), notes:str=Form("")):
    x=require_role(request,"admin","operations","accountant")
    if x:return x
    con=db(); ch=con.execute("SELECT * FROM sales_channels WHERE name=? AND active=1",(source,)).fetchone()
    if not ch: ch=con.execute("SELECT * FROM sales_channels WHERE name='Other'").fetchone()
    rate=float(ch["default_commission_rate"] or 0); commission=round(float(retail_amount)*rate/100.0,3)
    expected=round(float(retail_amount)-commission,3)
    try:
        cur=con.execute("""INSERT INTO bookings(service_datetime,booking_ref,product,option_name,traveler_name,email,phone,pax,price,net_price,currency,source,pickup,notes,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'Confirmed')""",
          (service_datetime.replace('T',' '),booking_ref.strip(),product,option_name,traveler_name,email,phone,pax,retail_amount,expected,currency.upper(),source,pickup,notes))
        bid=cur.lastrowid; exvat,vat=vat_breakdown(retail_amount,float(ch["vat_rate"] or DEFAULT_VAT_RATE),bool(ch["vat_inclusive"]))
        con.execute("""INSERT INTO booking_finance(booking_id,channel_id,retail_amount,currency,sales_vat_rate,sales_vat_amount,revenue_ex_vat,commission_rate,commission_amount,expected_payout,receivable_balance,payment_status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)""",
          (bid,ch["id"],retail_amount,currency.upper(),ch["vat_rate"],vat,exvat,rate,commission,expected,expected,"Unpaid"))
        con.commit()
    except sqlite3.IntegrityError:
        con.close(); flash(request,"Booking reference already exists.","danger"); return RedirectResponse("/bookings",303)
    con.close(); audit(request,"CREATE","booking",bid,f"{source} {booking_ref}"); flash(request,"Booking created and finance record calculated.","success"); return RedirectResponse(f"/bookings/{bid}",303)

@app.get("/bookings/{bid}", response_class=HTMLResponse)
def booking_detail(request: Request,bid:int):
    x=require_login(request)
    if x:return x
    con=db()
    if not staff_can_access_booking(con,request,bid): con.close(); raise HTTPException(403)
    b=con.execute("SELECT b.*,v.name vehicle_name,v.plate_no,v.make_model FROM bookings b LEFT JOIN vehicles v ON v.id=b.vehicle_id WHERE b.id=?",(bid,)).fetchone()
    if not b: con.close(); raise HTTPException(404)
    assigned=con.execute("SELECT bs.*,u.name,u.phone,u.role FROM booking_staff bs JOIN users u ON u.id=bs.user_id WHERE bs.booking_id=?",(bid,)).fetchall()
    staff=con.execute("SELECT * FROM users WHERE active=1 AND role IN ('driver','guide') ORDER BY name").fetchall()
    vehicles=con.execute("SELECT * FROM vehicles WHERE active=1 ORDER BY name").fetchall()
    expenses=con.execute("SELECT e.*,u.name user_name FROM expenses e JOIN users u ON u.id=e.user_id WHERE e.booking_id=? ORDER BY e.id DESC",(bid,)).fetchall()
    documents=con.execute("SELECT d.*,u.name user_name FROM booking_documents d JOIN users u ON u.id=d.uploaded_by WHERE d.booking_id=? AND (?='admin' OR d.archived=0) ORDER BY d.id DESC",(bid,request.session["role"])).fetchall()
    incidents=con.execute("SELECT i.*,u.name user_name FROM incidents i LEFT JOIN users u ON u.id=i.user_id WHERE i.booking_id=? ORDER BY i.id DESC",(bid,)).fetchall()
    expense_bhd=con.execute("SELECT COALESCE(SUM(amount),0) n FROM expenses WHERE booking_id=? AND currency='BHD' AND status IN ('Approved','Paid')",(bid,)).fetchone()["n"]
    finance=ensure_booking_finance(con,bid); channel=con.execute("SELECT * FROM sales_channels WHERE id=?",(finance["channel_id"],)).fetchone() if finance and finance["channel_id"] else None
    con.commit(); con.close(); return templates.TemplateResponse("booking_detail.html",ctx(request,b=b,assigned=assigned,staff=staff,vehicles=vehicles,expenses=expenses,documents=documents,incidents=incidents,expense_bhd=expense_bhd,finance=finance,channel=channel))

@app.post("/bookings/{bid}/assign")
def assign_booking(request:Request,bid:int,user_id:int=Form(...),assignment_role:str=Form("")):
    x=require_role(request,"admin","operations")
    if x:return x
    con=db(); con.execute("INSERT OR IGNORE INTO booking_staff(booking_id,user_id,assignment_role) VALUES(?,?,?)",(bid,user_id,assignment_role)); con.commit(); con.close(); audit(request,"ASSIGN","booking",bid,f"user {user_id}"); flash(request,"Staff assigned.","success"); return RedirectResponse(f"/bookings/{bid}",303)

@app.post("/assignments/{aid}/respond")
def assignment_respond(request:Request,aid:int,acceptance_status:str=Form(...),response_note:str=Form("")):
    x=require_role(request,"driver","guide")
    if x:return x
    if acceptance_status not in ("Accepted","Declined","Replacement Requested"): raise HTTPException(400)
    con=db(); row=con.execute("SELECT * FROM booking_staff WHERE id=? AND user_id=?",(aid,request.session["user_id"])).fetchone()
    if not row: con.close(); raise HTTPException(403)
    con.execute("UPDATE booking_staff SET acceptance_status=?,response_note=?,responded_at=CURRENT_TIMESTAMP WHERE id=?",(acceptance_status,response_note,aid)); con.commit(); con.close(); audit(request,"RESPOND","assignment",aid,acceptance_status); return RedirectResponse(f"/bookings/{row['booking_id']}",303)

@app.post("/bookings/{bid}/status")
def booking_status(request:Request,bid:int,status:str=Form(...)):
    x=require_login(request)
    if x:return x
    if status not in BOOKING_STATUSES: raise HTTPException(400)
    con=db()
    if not staff_can_access_booking(con,request,bid): con.close(); raise HTTPException(403)
    con.execute("UPDATE bookings SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(status,bid)); con.commit(); con.close(); audit(request,"STATUS","booking",bid,status); return RedirectResponse(f"/bookings/{bid}",303)

@app.post("/bookings/{bid}/vehicle")
def booking_vehicle(request:Request,bid:int,vehicle_id:Optional[str]=Form(None)):
    x=require_role(request,"admin","operations")
    if x:return x
    con=db(); con.execute("UPDATE bookings SET vehicle_id=? WHERE id=?",(int(vehicle_id) if vehicle_id else None,bid)); con.commit(); con.close(); audit(request,"VEHICLE","booking",bid,vehicle_id or "none"); return RedirectResponse(f"/bookings/{bid}",303)

@app.post("/bookings/{bid}/documents")
async def booking_document_upload(request:Request,bid:int,document_type:str=Form("Other"),note:str=Form(""),document:UploadFile=File(...)):
    x=require_login(request)
    if x:return x
    con=db()
    if not staff_can_access_booking(con,request,bid): con.close(); raise HTTPException(403)
    if not con.execute("SELECT 1 FROM bookings WHERE id=?",(bid,)).fetchone(): con.close(); raise HTTPException(404)
    con.close()
    meta=await save_upload(document,"booking")
    con=db(); cur=con.execute("INSERT INTO booking_documents(booking_id,uploaded_by,document_type,stored_filename,original_filename,mime_type,file_size,note) VALUES(?,?,?,?,?,?,?,?)",(bid,request.session["user_id"],document_type,meta["stored"],meta["original"],meta["mime"],meta["size"],note)); con.commit(); did=cur.lastrowid; con.close(); audit(request,"UPLOAD","booking_document",did,meta["original"]); flash(request,"Document uploaded successfully.","success"); return RedirectResponse(f"/bookings/{bid}",303)

@app.get("/documents/{did}")
def document_download(request:Request,did:int):
    x=require_login(request)
    if x:return x
    con=db(); d=con.execute("SELECT * FROM booking_documents WHERE id=?",(did,)).fetchone()
    if not d: con.close(); raise HTTPException(404)
    if not staff_can_access_booking(con,request,d["booking_id"]): con.close(); raise HTTPException(403)
    con.close(); p=UPLOAD_DIR/d["stored_filename"]
    if not p.exists(): raise HTTPException(404,"Stored file missing")
    return FileResponse(p,media_type=d["mime_type"] or "application/octet-stream",filename=d["original_filename"],content_disposition_type="inline")

@app.get("/expenses", response_class=HTMLResponse)
def expenses_get(request:Request):
    x=require_login(request)
    if x:return x
    con=db(); uid=request.session["user_id"]; role=request.session["role"]
    if role in ("driver","guide"):
        rows=con.execute("SELECT e.*,b.booking_ref,u.name user_name FROM expenses e LEFT JOIN bookings b ON b.id=e.booking_id JOIN users u ON u.id=e.user_id WHERE e.user_id=? AND e.archived=0 ORDER BY e.id DESC",(uid,)).fetchall()
        bks=con.execute("SELECT b.* FROM bookings b JOIN booking_staff bs ON bs.booking_id=b.id WHERE bs.user_id=? ORDER BY b.service_datetime DESC",(uid,)).fetchall()
    else:
        rows=con.execute("SELECT e.*,b.booking_ref,u.name user_name FROM expenses e LEFT JOIN bookings b ON b.id=e.booking_id JOIN users u ON u.id=e.user_id WHERE e.archived=0 ORDER BY e.id DESC").fetchall()
        bks=con.execute("SELECT * FROM bookings ORDER BY service_datetime DESC LIMIT 300").fetchall()
    con.close(); return templates.TemplateResponse("expenses.html",ctx(request,rows=rows,bks=bks))

@app.post("/expenses")
async def expense_create(request:Request,booking_id:Optional[str]=Form(None),expense_date:str=Form(...),category:str=Form(...),amount:float=Form(...),currency:str=Form("BHD"),description:str=Form(""),submit_now:str=Form("1"),receipt:Optional[UploadFile]=File(None)):
    x=require_login(request)
    if x:return x
    if category not in EXPENSE_CATEGORIES: raise HTTPException(400)
    meta=None
    if receipt and receipt.filename: meta=await save_upload(receipt,"receipt")
    status="Submitted" if submit_now=="1" else "Draft"
    con=db(); cur=con.execute("INSERT INTO expenses(user_id,booking_id,expense_date,category,description,amount,currency,receipt_file,original_filename,receipt_mime,status,submitted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,CASE WHEN ?='Submitted' THEN CURRENT_TIMESTAMP ELSE NULL END)",(request.session["user_id"],int(booking_id) if booking_id else None,expense_date,category,description,amount,currency,meta["stored"] if meta else None,meta["original"] if meta else None,meta["mime"] if meta else None,status,status)); con.commit(); eid=cur.lastrowid; con.close(); audit(request,"CREATE","expense",eid,status); flash(request,"Expense saved.","success"); return RedirectResponse("/expenses",303)

@app.get("/receipts/{eid}")
def receipt_view(request:Request,eid:int):
    x=require_login(request)
    if x:return x
    con=db(); e=con.execute("SELECT * FROM expenses WHERE id=?",(eid,)).fetchone()
    if not e or not e["receipt_file"]: con.close(); raise HTTPException(404)
    if request.session["role"] in ("driver","guide") and e["user_id"]!=request.session["user_id"]: con.close(); raise HTTPException(403)
    con.close(); p=UPLOAD_DIR/e["receipt_file"]
    if not p.exists(): raise HTTPException(404,"Stored receipt missing")
    return FileResponse(p,media_type=e["receipt_mime"] or "application/octet-stream",filename=e["original_filename"] or p.name,content_disposition_type="inline")

@app.post("/expenses/{eid}/review")
def expense_review(request:Request,eid:int,status:str=Form(...),admin_note:str=Form("")):
    x=require_role(request,"admin","accountant")
    if x:return x
    if status not in ("Approved","Rejected","Paid"): raise HTTPException(400)
    col = "approved_at" if status=="Approved" else "paid_at" if status=="Paid" else None
    con=db()
    if col: con.execute(f"UPDATE expenses SET status=?,admin_note=?,{col}=CURRENT_TIMESTAMP WHERE id=?",(status,admin_note,eid))
    else: con.execute("UPDATE expenses SET status=?,admin_note=? WHERE id=?",(status,admin_note,eid))
    con.commit(); con.close(); audit(request,"REVIEW","expense",eid,status); return RedirectResponse("/expenses",303)

@app.get("/vehicles", response_class=HTMLResponse)
def vehicles_get(request:Request):
    x=require_role(request,"admin","operations")
    if x:return x
    con=db(); rows=con.execute("SELECT * FROM vehicles ORDER BY active DESC,name").fetchall(); con.close(); return templates.TemplateResponse("vehicles.html",ctx(request,rows=rows))

@app.post("/vehicles")
def vehicles_post(request:Request,name:str=Form(...),plate_no:str=Form(""),make_model:str=Form(""),seats:int=Form(5),notes:str=Form("")):
    x=require_role(request,"admin","operations")
    if x:return x
    con=db(); con.execute("INSERT INTO vehicles(name,plate_no,make_model,seats,notes) VALUES(?,?,?,?,?)",(name,plate_no,make_model,seats,notes)); con.commit(); con.close(); return RedirectResponse("/vehicles",303)

@app.get("/users", response_class=HTMLResponse)
def users_get(request:Request):
    x=require_role(request,"admin")
    if x:return x
    con=db(); rows=con.execute("SELECT * FROM users ORDER BY active DESC,name").fetchall(); con.close(); return templates.TemplateResponse("users.html",ctx(request,rows=rows))

@app.post("/users")
def users_post(request:Request,name:str=Form(...),email:str=Form(...),phone:str=Form(""),role:str=Form(...),password:str=Form(...)):
    x=require_role(request,"admin")
    if x:return x
    if role not in ROLES or len(password)<8: raise HTTPException(400)
    con=db()
    try: con.execute("INSERT INTO users(name,email,password_hash,role,phone) VALUES(?,?,?,?,?)",(name,email.lower(),hash_password(password),role,phone)); con.commit()
    except sqlite3.IntegrityError: con.close(); flash(request,"Email already exists.","danger"); return RedirectResponse("/users",303)
    con.close(); return RedirectResponse("/users",303)


@app.get("/payments", response_class=HTMLResponse)
def payments_get(request:Request):
    x=require_role(request,"admin","accountant","operations")
    if x:return x
    con=db()
    batches=con.execute("SELECT p.*,u.name uploaded_by_name FROM payment_batches p JOIN users u ON u.id=p.uploaded_by ORDER BY p.id DESC").fetchall()
    channels=con.execute("SELECT * FROM sales_channels WHERE active=1 ORDER BY name").fetchall()
    con.close()
    return templates.TemplateResponse("payments.html",ctx(request,batches=batches,channels=channels))

@app.post("/payments/upload")
async def payment_upload(request:Request, source:str=Form("GetYourGuide"), period_start:str=Form(...), period_end:str=Form(...), statement_date:str=Form(""), currency:str=Form("USD"), notes:str=Form(""), statement:UploadFile=File(...)):
    x=require_role(request,"admin","accountant","operations")
    if x:return x
    if period_end < period_start: raise HTTPException(400,"Period end cannot be before period start.")
    if not statement or not statement.filename: raise HTTPException(400,"Choose a payment statement file.")
    raw=await statement.read(MAX_UPLOAD_MB*1024*1024+1)
    if len(raw)>MAX_UPLOAD_MB*1024*1024: raise HTTPException(413,f"File is larger than {MAX_UPLOAD_MB} MB.")
    ext=Path(statement.filename).suffix.lower()
    if ext not in {".pdf",".csv",".tsv",".xlsx"}: raise HTTPException(400,"Use PDF, CSV, TSV or XLSX for payment statements.")
    try: parsed=parse_payment_statement(statement.filename,raw)
    except ValueError as e:
        flash(request,str(e),"danger"); return RedirectResponse("/payments",303)
    stored=f"payment_{safe_upload_name(statement.filename)}"; target=UPLOAD_DIR/stored; target.write_bytes(raw)
    if not target.exists() or target.stat().st_size!=len(raw): raise HTTPException(500,"Payment statement could not be saved correctly.")
    mime=statement.content_type or mimetypes.guess_type(statement.filename)[0] or "application/octet-stream"
    con=db(); cur=con.execute("""INSERT INTO payment_batches(source,period_start,period_end,statement_date,currency,stored_filename,original_filename,mime_type,file_size,uploaded_by,notes)
                               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",(source,period_start,period_end,statement_date or None,currency.upper(),stored,Path(statement.filename).name,mime,len(raw),request.session["user_id"],notes)); batch_id=cur.lastrowid
    result=reconcile_payment_batch(con,batch_id,source,period_start,period_end,currency.upper(),parsed); con.commit(); con.close()
    audit(request,"RECONCILE","payment_batch",batch_id,f"{result['status']} variance {result['variance']}")
    flash(request,f"Statement reconciled. {result['issues']} item(s) need review.","success" if result['issues']==0 else "info")
    return RedirectResponse(f"/payments/{batch_id}",303)

@app.get("/payments/{batch_id}", response_class=HTMLResponse)
def payment_detail(request:Request,batch_id:int):
    x=require_role(request,"admin","accountant","operations")
    if x:return x
    con=db(); batch=con.execute("SELECT p.*,u.name uploaded_by_name FROM payment_batches p JOIN users u ON u.id=p.uploaded_by WHERE p.id=?",(batch_id,)).fetchone()
    if not batch: con.close(); raise HTTPException(404)
    lines=con.execute("SELECT l.*,b.service_datetime,b.traveler_name,b.product FROM payment_lines l LEFT JOIN bookings b ON b.id=l.booking_id WHERE l.batch_id=? ORDER BY CASE l.reconciliation_status WHEN 'Exact Match' THEN 9 ELSE 1 END, l.booking_ref",(batch_id,)).fetchall()
    counts={r["reconciliation_status"]:r["n"] for r in con.execute("SELECT reconciliation_status,COUNT(*) n FROM payment_lines WHERE batch_id=? GROUP BY reconciliation_status",(batch_id,)).fetchall()}
    con.close(); return templates.TemplateResponse("payment_detail.html",ctx(request,batch=batch,lines=lines,counts=counts))

@app.get("/payments/{batch_id}/statement")
def payment_statement_view(request:Request,batch_id:int):
    x=require_role(request,"admin","accountant","operations")
    if x:return x
    con=db(); batch=con.execute("SELECT * FROM payment_batches WHERE id=?",(batch_id,)).fetchone(); con.close()
    if not batch: raise HTTPException(404)
    p=UPLOAD_DIR/batch["stored_filename"]
    if not p.exists(): raise HTTPException(404,"Stored payment statement missing")
    return FileResponse(p,media_type=batch["mime_type"] or "application/octet-stream",filename=batch["original_filename"],content_disposition_type="inline")

@app.get("/payments/{batch_id}/export.csv")
def payment_export(request:Request,batch_id:int):
    x=require_role(request,"admin","accountant","operations")
    if x:return x
    con=db(); rows=con.execute("SELECT booking_ref,paid_amount,expected_amount,currency,variance,reconciliation_status FROM payment_lines WHERE batch_id=? ORDER BY booking_ref",(batch_id,)).fetchall(); con.close()
    out=io.StringIO(); w=csv.writer(out); w.writerow(["Booking Reference","Paid Amount","Expected Net","Currency","Variance","Status"])
    for r in rows: w.writerow(list(r))
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":f"attachment; filename=payment_reconciliation_{batch_id}.csv"})

@app.get("/channels", response_class=HTMLResponse)
def channels_get(request:Request):
    x=require_role(request,"admin","accountant","operations")
    if x:return x
    con=db(); rows=con.execute("SELECT * FROM sales_channels ORDER BY active DESC,name").fetchall(); con.close()
    return templates.TemplateResponse("channels.html",ctx(request,rows=rows))

@app.post("/channels")
def channels_post(request:Request,name:str=Form(...),code:str=Form(""),channel_type:str=Form("OTA"),default_commission_rate:float=Form(0),vat_rate:float=Form(DEFAULT_VAT_RATE),vat_inclusive:str=Form("1"),notes:str=Form("")):
    x=require_role(request,"admin","accountant")
    if x:return x
    con=db()
    try:
        con.execute("INSERT INTO sales_channels(name,code,channel_type,default_commission_rate,vat_rate,vat_inclusive,notes) VALUES(?,?,?,?,?,?,?)",(name,code.upper() or None,channel_type,default_commission_rate,vat_rate,1 if vat_inclusive=='1' else 0,notes)); con.commit()
    except sqlite3.IntegrityError:
        con.close(); flash(request,"Channel name or code already exists.","danger"); return RedirectResponse("/channels",303)
    con.close(); flash(request,"Sales channel added.","success"); return RedirectResponse("/channels",303)

@app.post("/channels/{cid}/update")
def channel_update(request:Request,cid:int,default_commission_rate:float=Form(0),vat_rate:float=Form(DEFAULT_VAT_RATE),vat_inclusive:str=Form("1"),active:str=Form("1"),notes:str=Form("")):
    x=require_role(request,"admin","accountant")
    if x:return x
    con=db(); con.execute("UPDATE sales_channels SET default_commission_rate=?,vat_rate=?,vat_inclusive=?,active=?,notes=? WHERE id=?",(default_commission_rate,vat_rate,1 if vat_inclusive=='1' else 0,1 if active=='1' else 0,notes,cid)); con.commit(); con.close(); flash(request,"Channel settings updated.","success"); return RedirectResponse("/channels",303)

@app.get("/finance", response_class=HTMLResponse)
def finance_get(request:Request):
    x=require_role(request,"admin","accountant","operations","viewer")
    if x:return x
    con=db(); initialize=[]
    for r in con.execute("SELECT id FROM bookings").fetchall(): ensure_booking_finance(con,r["id"])
    con.commit()
    totals=con.execute("""SELECT COUNT(*) bookings,COALESCE(SUM(retail_amount),0) gross_sales,COALESCE(SUM(sales_vat_amount),0) output_vat,COALESCE(SUM(revenue_ex_vat),0) sales_ex_vat,COALESCE(SUM(commission_amount),0) ota_commission,COALESCE(SUM(commission_vat),0) commission_vat,COALESCE(SUM(expected_payout),0) expected_payout,COALESCE(SUM(actual_payout),0) actual_payout,COALESCE(SUM(receivable_balance),0) receivable FROM booking_finance""").fetchone()
    by_channel=con.execute("""SELECT c.name,c.channel_type,COUNT(f.id) bookings,COALESCE(SUM(f.retail_amount),0) gross_sales,COALESCE(SUM(f.sales_vat_amount),0) output_vat,COALESCE(SUM(f.commission_amount),0) commission,COALESCE(SUM(f.expected_payout),0) expected_payout,COALESCE(SUM(f.actual_payout),0) actual_payout,COALESCE(SUM(f.receivable_balance),0) receivable FROM sales_channels c LEFT JOIN booking_finance f ON f.channel_id=c.id GROUP BY c.id ORDER BY gross_sales DESC""").fetchall()
    recent=con.execute("""SELECT b.id,b.booking_ref,b.service_datetime,b.traveler_name,b.source,f.* FROM booking_finance f JOIN bookings b ON b.id=f.booking_id ORDER BY b.service_datetime DESC LIMIT 250""").fetchall()
    con.close(); return templates.TemplateResponse("finance.html",ctx(request,totals=totals,by_channel=by_channel,recent=recent))

@app.post("/bookings/{bid}/finance")
def booking_finance_update(request:Request,bid:int,retail_amount:float=Form(...),sales_vat_rate:float=Form(DEFAULT_VAT_RATE),commission_amount:float=Form(0),commission_vat:float=Form(0),manual_adjustments:float=Form(0),expected_payout:float=Form(...)):
    x=require_role(request,"admin","accountant")
    if x:return x
    con=db(); f=ensure_booking_finance(con,bid)
    if not f: con.close(); raise HTTPException(404)
    exvat,vat=vat_breakdown(retail_amount,sales_vat_rate,True); actual=float(f["actual_payout"] or 0); balance=round(expected_payout-actual,3)
    status="Paid" if abs(balance)<=0.01 and expected_payout!=0 else ("Partially Paid" if actual>0 else "Unpaid")
    con.execute("""UPDATE booking_finance SET retail_amount=?,sales_vat_rate=?,sales_vat_amount=?,revenue_ex_vat=?,commission_amount=?,commission_vat=?,manual_adjustments=?,expected_payout=?,receivable_balance=?,payment_status=?,updated_at=CURRENT_TIMESTAMP WHERE booking_id=?""",(retail_amount,sales_vat_rate,vat,exvat,abs(commission_amount),abs(commission_vat),manual_adjustments,expected_payout,balance,status,bid))
    con.execute("UPDATE bookings SET price=?,net_price=? WHERE id=?",(retail_amount,expected_payout,bid)); con.commit(); con.close(); audit(request,"UPDATE","booking_finance",bid,"manual finance update"); flash(request,"Booking finance updated.","success"); return RedirectResponse(f"/bookings/{bid}",303)

@app.post("/bookings/{bid}/record-payment")
def booking_record_payment(request:Request,bid:int,amount:float=Form(...),note:str=Form("")):
    x=require_role(request,"admin","accountant")
    if x:return x
    con=db(); f=ensure_booking_finance(con,bid)
    if not f: con.close(); raise HTTPException(404)
    new_actual=round(float(f["actual_payout"] or 0)+float(amount),3); expected=float(f["expected_payout"] or 0); bal=round(expected-new_actual,3)
    status="Paid" if abs(bal)<=0.01 else ("Partially Paid" if new_actual>0 else "Unpaid")
    con.execute("UPDATE booking_finance SET actual_payout=?,receivable_balance=?,payment_status=?,updated_at=CURRENT_TIMESTAMP WHERE booking_id=?",(new_actual,bal,status,bid)); con.commit(); con.close()
    audit(request,"PAYMENT","booking_finance",bid,f"Recorded {amount}: {note}"); flash(request,"Payment recorded.","success"); return RedirectResponse(f"/bookings/{bid}",303)

@app.get("/finance/vat.csv")
def finance_vat_export(request:Request):
    x=require_role(request,"admin","accountant")
    if x:return x
    con=db(); rows=con.execute("""SELECT b.service_datetime,b.booking_ref,b.source,b.traveler_name,f.currency,f.retail_amount,f.sales_vat_rate,f.sales_vat_amount,f.revenue_ex_vat,f.commission_amount,f.commission_vat,f.expected_payout,f.actual_payout,f.receivable_balance,f.payment_status FROM booking_finance f JOIN bookings b ON b.id=f.booking_id ORDER BY b.service_datetime""").fetchall(); con.close()
    out=io.StringIO(); w=csv.writer(out); w.writerow(["Service Date","Booking Reference","Source","Traveler","Currency","Gross Sale VAT Inclusive","VAT Rate %","Output VAT","Sales Ex VAT","OTA Commission","VAT on OTA Services","Expected Payout","Actual Payout","Receivable","Payment Status"]); [w.writerow(list(r)) for r in rows]
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=high_sky_vat_sales_finance.csv"})

@app.post("/bookings/{bid}/edit")
def admin_booking_edit(request:Request,bid:int,service_datetime:str=Form(...),booking_ref:str=Form(...),source:str=Form(...),traveler_name:str=Form(...),product:str=Form(...),option_name:str=Form(""),pax:int=Form(1),country:str=Form(""),email:str=Form(""),phone:str=Form(""),pickup:str=Form(""),notes:str=Form(""),status:str=Form("Confirmed")):
    x=require_role(request,"admin")
    if x:return x
    if status not in BOOKING_STATUSES: raise HTTPException(400)
    con=db()
    try:
        con.execute("""UPDATE bookings SET service_datetime=?,booking_ref=?,source=?,traveler_name=?,product=?,option_name=?,pax=?,country=?,email=?,phone=?,pickup=?,notes=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                    (service_datetime.replace('T',' '),booking_ref.strip(),source,traveler_name,product,option_name,pax,country,email,phone,pickup,notes,status,bid))
        con.commit()
    except sqlite3.IntegrityError:
        con.close(); flash(request,"Booking reference already exists.","danger"); return RedirectResponse(f"/bookings/{bid}",303)
    con.close(); audit(request,"ADMIN_EDIT","booking",bid,"full booking edit"); flash(request,"Booking updated. Existing finance, documents, assignments and expenses were retained.","success"); return RedirectResponse(f"/bookings/{bid}",303)

@app.post("/bookings/{bid}/archive")
def admin_booking_archive(request:Request,bid:int,archived:int=Form(1)):
    x=require_role(request,"admin")
    if x:return x
    con=db(); con.execute("UPDATE bookings SET archived=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(1 if archived else 0,bid)); con.commit(); con.close(); audit(request,"ARCHIVE" if archived else "RESTORE","booking",bid); flash(request,"Booking archived, not deleted." if archived else "Booking restored.","success"); return RedirectResponse("/bookings",303)

@app.post("/assignments/{aid}/admin-remove")
def admin_assignment_remove(request:Request,aid:int):
    x=require_role(request,"admin")
    if x:return x
    con=db(); row=con.execute("SELECT booking_id FROM booking_staff WHERE id=?",(aid,)).fetchone()
    if not row: con.close(); raise HTTPException(404)
    bid=row["booking_id"]; con.execute("DELETE FROM booking_staff WHERE id=?",(aid,)); con.commit(); con.close(); audit(request,"ADMIN_REMOVE","assignment",aid); flash(request,"Assignment removed. Booking and staff records were retained.","success"); return RedirectResponse(f"/bookings/{bid}",303)

@app.post("/documents/{did}/admin-update")
def admin_document_update(request:Request,did:int,document_type:str=Form("Other"),note:str=Form(""),archived:int=Form(0)):
    x=require_role(request,"admin")
    if x:return x
    con=db(); row=con.execute("SELECT booking_id FROM booking_documents WHERE id=?",(did,)).fetchone()
    if not row: con.close(); raise HTTPException(404)
    con.execute("UPDATE booking_documents SET document_type=?,note=?,archived=? WHERE id=?",(document_type,note,1 if archived else 0,did)); con.commit(); bid=row["booking_id"]; con.close(); audit(request,"ADMIN_EDIT","booking_document",did); flash(request,"Document record updated. File retained.","success"); return RedirectResponse(f"/bookings/{bid}",303)

@app.post("/expenses/{eid}/admin-edit")
def admin_expense_edit(request:Request,eid:int,expense_date:str=Form(...),category:str=Form(...),description:str=Form(""),amount:float=Form(...),currency:str=Form("BHD"),status:str=Form("Draft"),admin_note:str=Form(""),archived:int=Form(0)):
    x=require_role(request,"admin")
    if x:return x
    if category not in EXPENSE_CATEGORIES or status not in EXPENSE_STATUSES: raise HTTPException(400)
    con=db(); con.execute("UPDATE expenses SET expense_date=?,category=?,description=?,amount=?,currency=?,status=?,admin_note=?,archived=? WHERE id=?",(expense_date,category,description,amount,currency,status,admin_note,1 if archived else 0,eid)); con.commit(); con.close(); audit(request,"ADMIN_EDIT","expense",eid); flash(request,"Expense updated. Receipt retained.","success"); return RedirectResponse("/expenses",303)

@app.post("/vehicles/{vid}/admin-edit")
def admin_vehicle_edit(request:Request,vid:int,name:str=Form(...),plate_no:str=Form(""),make_model:str=Form(""),seats:int=Form(5),notes:str=Form(""),active:int=Form(1)):
    x=require_role(request,"admin")
    if x:return x
    con=db(); con.execute("UPDATE vehicles SET name=?,plate_no=?,make_model=?,seats=?,notes=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(name,plate_no,make_model,seats,notes,1 if active else 0,vid)); con.commit(); con.close(); audit(request,"ADMIN_EDIT","vehicle",vid); flash(request,"Vehicle updated.","success"); return RedirectResponse("/vehicles",303)

@app.post("/users/{uid}/admin-edit")
def admin_user_edit(request:Request,uid:int,name:str=Form(...),email:str=Form(...),phone:str=Form(""),role:str=Form(...),active:int=Form(1),new_password:str=Form("")):
    x=require_role(request,"admin")
    if x:return x
    if role not in ROLES: raise HTTPException(400)
    con=db()
    try:
        if new_password:
            if len(new_password)<8: con.close(); flash(request,"Password must be at least 8 characters.","danger"); return RedirectResponse("/users",303)
            con.execute("UPDATE users SET name=?,email=?,phone=?,role=?,active=?,password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(name,email.strip().lower(),phone,role,1 if active else 0,hash_password(new_password),uid))
        else:
            con.execute("UPDATE users SET name=?,email=?,phone=?,role=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(name,email.strip().lower(),phone,role,1 if active else 0,uid))
        con.commit()
    except sqlite3.IntegrityError:
        con.close(); flash(request,"That email is already used by another account.","danger"); return RedirectResponse("/users",303)
    con.close(); audit(request,"ADMIN_EDIT","user",uid); flash(request,"User updated.","success"); return RedirectResponse("/users",303)

@app.post("/channels/{cid}/admin-edit")
def admin_channel_full_edit(request:Request,cid:int,name:str=Form(...),code:str=Form(""),channel_type:str=Form("OTA"),default_commission_rate:float=Form(0),vat_rate:float=Form(DEFAULT_VAT_RATE),vat_inclusive:int=Form(1),active:int=Form(1),notes:str=Form("")):
    x=require_role(request,"admin")
    if x:return x
    if channel_type not in CHANNEL_TYPES: raise HTTPException(400)
    con=db()
    try:
        con.execute("UPDATE sales_channels SET name=?,code=?,channel_type=?,default_commission_rate=?,vat_rate=?,vat_inclusive=?,active=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(name,code.upper() or None,channel_type,default_commission_rate,vat_rate,1 if vat_inclusive else 0,1 if active else 0,notes,cid)); con.commit()
    except sqlite3.IntegrityError:
        con.close(); flash(request,"Channel name or code already exists.","danger"); return RedirectResponse("/channels",303)
    con.close(); audit(request,"ADMIN_EDIT","sales_channel",cid); flash(request,"Channel fully updated.","success"); return RedirectResponse("/channels",303)

@app.get("/settings", response_class=HTMLResponse)
def admin_settings_get(request:Request):
    x=require_role(request,"admin")
    if x:return x
    con=db(); rows=con.execute("SELECT * FROM system_settings ORDER BY key").fetchall(); con.close(); return templates.TemplateResponse("settings.html",ctx(request,rows=rows,data_dir=str(DATA_DIR),upload_dir=str(UPLOAD_DIR),db_path=str(DB_PATH)))

@app.post("/settings")
def admin_settings_save(request:Request,company_name:str=Form(...),company_phone:str=Form(""),company_email:str=Form(""),default_vat_rate:float=Form(10)):
    x=require_role(request,"admin")
    if x:return x
    con=db(); set_setting(con,'company_name',company_name); set_setting(con,'company_phone',company_phone); set_setting(con,'company_email',company_email); set_setting(con,'default_vat_rate',str(default_vat_rate)); con.commit(); con.close(); audit(request,"ADMIN_EDIT","settings",None,"company/default settings"); flash(request,"System settings saved. Existing records were not changed.","success"); return RedirectResponse("/settings",303)

@app.get("/admin/archived", response_class=HTMLResponse)
def admin_archived(request:Request):
    x=require_role(request,"admin")
    if x:return x
    con=db(); bookings=con.execute("SELECT * FROM bookings WHERE archived=1 ORDER BY service_datetime DESC").fetchall(); expenses=con.execute("SELECT e.*,u.name user_name FROM expenses e LEFT JOIN users u ON u.id=e.user_id WHERE e.archived=1 ORDER BY e.id DESC").fetchall(); con.close(); return templates.TemplateResponse("archived.html",ctx(request,bookings=bookings,expenses=expenses))

@app.get("/reports", response_class=HTMLResponse)
def reports(request:Request):
    x=require_role(request,"admin","operations","accountant","viewer")
    if x:return x
    con=db(); by_product=con.execute("SELECT product,COUNT(*) bookings,SUM(pax) guests,SUM(price) sales,SUM(net_price) net FROM bookings GROUP BY product ORDER BY bookings DESC").fetchall(); by_source=con.execute("SELECT source,COUNT(*) bookings,SUM(net_price) net FROM bookings GROUP BY source").fetchall(); by_month=con.execute("SELECT substr(service_datetime,1,7) month,COUNT(*) bookings,SUM(pax) guests,SUM(net_price) net FROM bookings GROUP BY month ORDER BY month DESC").fetchall(); exp=con.execute("SELECT category,currency,COUNT(*) claims,SUM(amount) amount FROM expenses WHERE status IN ('Approved','Paid') GROUP BY category,currency").fetchall(); profitability=con.execute("SELECT b.*,COALESCE((SELECT SUM(e.amount) FROM expenses e WHERE e.booking_id=b.id AND e.currency='BHD' AND e.status IN ('Approved','Paid')),0) approved_expenses_bhd FROM bookings b ORDER BY b.service_datetime DESC LIMIT 200").fetchall(); con.close(); return templates.TemplateResponse("reports.html",ctx(request,by_product=by_product,by_source=by_source,by_month=by_month,exp=exp,profitability=profitability))

@app.get("/export/bookings.csv")
def export_bookings(request:Request):
    x=require_role(request,"admin","operations","accountant","viewer")
    if x:return x
    con=db(); rows=con.execute("SELECT * FROM bookings ORDER BY service_datetime").fetchall(); con.close(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ["No data"]); [w.writerow(list(r)) for r in rows]; return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=high_sky_bookings.csv"})

@app.get("/audit", response_class=HTMLResponse)
def audit_view(request:Request):
    x=require_role(request,"admin")
    if x:return x
    con=db(); rows=con.execute("SELECT a.*,u.name user_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 500").fetchall(); con.close(); return templates.TemplateResponse("audit.html",ctx(request,rows=rows))
