"""PostgreSQL support while retaining SQLite for the offline desktop portal."""
import re
import os
import sqlite3


class Row(dict):
    # sqlite3.Row iterates over values, which the CSV exports rely on.
    def __iter__(self):
        return iter(self.values())


def postgres_sql(sql):
    # Convert placeholders outside SQL string literals only.
    parts = re.split(r"('(?:''|[^'])*')", sql)
    for i in range(0, len(parts), 2):
        parts[i] = parts[i].replace('?', '%s')
    sql = ''.join(parts).strip().rstrip(';')
    sql = re.sub(r'INTEGER PRIMARY KEY AUTOINCREMENT', 'BIGSERIAL PRIMARY KEY', sql, flags=re.I)
    sql = re.sub(r'\bREAL\b', 'DOUBLE PRECISION', sql, flags=re.I)
    sql = re.sub(r'\bGROUP_CONCAT\(', 'STRING_AGG(', sql, flags=re.I)
    if re.match(r'INSERT\s+OR\s+IGNORE\b', sql, re.I):
        sql = re.sub(r'INSERT\s+OR\s+IGNORE\b', 'INSERT', sql, count=1, flags=re.I)
        sql += ' ON CONFLICT DO NOTHING'
    return sql


class Cursor:
    def __init__(self, connection):
        self.connection = connection
        self.cursor = connection.raw.cursor()
        self.lastrowid = None

    def execute(self, sql, parameters=()):
        sql = postgres_sql(sql)
        insert = re.match(r'INSERT INTO\s+(\w+)', sql, re.I)
        wants_id = insert and insert.group(1).lower() != 'system_settings'
        if wants_id:
            sql += ' RETURNING id'
        try:
            self.cursor.execute(sql, parameters or None)
        except self.connection.psycopg.IntegrityError as error:
            raise sqlite3.IntegrityError(str(error)) from error
        self.lastrowid = None
        if wants_id:
            row = self.cursor.fetchone()
            self.lastrowid = row['id'] if row else None
        return self

    def executescript(self, script):
        for statement in script.split(';'):
            if statement.strip():
                self.execute(statement)
        return self

    def executemany(self, sql, values):
        for parameters in values:
            self.execute(sql, parameters)
        return self

    def fetchone(self):
        row = self.cursor.fetchone()
        return Row(row) if row is not None else None

    def fetchall(self):
        return [Row(row) for row in self.cursor.fetchall()]


class PostgresConnection:
    def __init__(self, url):
        import psycopg
        from psycopg.rows import dict_row
        self.psycopg = psycopg
        self.raw = psycopg.connect(url, row_factory=dict_row, connect_timeout=15, prepare_threshold=None, sslmode="require" if os.environ.get("APP_ENV") == "production" else "prefer")
        self.raw.execute('SET search_path TO high_sky, public')

    def cursor(self):
        return Cursor(self)

    def execute(self, sql, parameters=()):
        return self.cursor().execute(sql, parameters)

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()
