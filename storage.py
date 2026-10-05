"""Private Supabase file storage accessed only by the authenticated backend."""
import os
from pathlib import Path
from urllib.parse import quote
import httpx
from fastapi import HTTPException


def configured():
    return bool(os.environ.get('SUPABASE_URL') and os.environ.get('SUPABASE_SERVICE_KEY'))


def request(method, filename=None, content=None, mime=None):
    base = os.environ['SUPABASE_URL'].rstrip('/')
    bucket = os.environ.get('SUPABASE_STORAGE_BUCKET', 'high-sky-documents')
    key = os.environ['SUPABASE_SERVICE_KEY']
    path = '/storage/v1/bucket/' + quote(bucket, safe='') if filename is None else '/storage/v1/object/' + quote(bucket, safe='') + '/' + quote(filename, safe='')
    headers = {'apikey': key, 'Authorization': 'Bearer ' + key}
    if mime:
        headers['Content-Type'] = mime
    try:
        response = httpx.request(method, base + path, headers=headers, content=content, timeout=45)
    except httpx.HTTPError as error:
        raise HTTPException(503, 'Document storage is temporarily unavailable') from error
    if response.status_code == 404:
        raise HTTPException(404, 'Stored document was not found')
    if not response.is_success:
        raise HTTPException(503, 'Document storage request failed')
    return response


def save(filename, content, mime, local_directory):
    if configured():
        request('POST', filename, content, mime)
    else:
        Path(local_directory, filename).write_bytes(content)


def read(filename, local_directory):
    if configured():
        return request('GET', filename).content
    path = Path(local_directory, filename)
    if not path.is_file():
        raise HTTPException(404, 'Stored document was not found')
    return path.read_bytes()


def healthy():
    info = request('GET').json()
    if info.get('public') is not False:
        raise RuntimeError('The document bucket must be private')
