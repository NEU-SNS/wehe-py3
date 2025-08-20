import os
import json
import tempfile
import shutil
import time

import pytest

from topologyFinder import *

TMP_CACHE_FOLDER = '/tmp/cache'

def contains_none(obj):
    """
    Recursively returns True if obj, or any nested item inside a dict/list,
    is exactly Python None.
    """
    if obj is None:
        return True
    if isinstance(obj, dict):
        return any(contains_none(v) for v in obj.values())
    if isinstance(obj, list):
        return any(contains_none(item) for item in obj)
    return False
  
def find_none(obj, path=""):
    """
    Recursively traverse obj (which can be a dict, list, or scalar).
    If any value is None, print its path.
    Returns True if at least one None was found, else False.
    """
    found = False
    if obj is None:
        print(f"None found at: {path or '<root>'}")
        return True

    if isinstance(obj, dict):
        for key, value in obj.items():
            subpath = f"{path}.{key}" if path else key
            if find_none(value, subpath):
                found = True

    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            subpath = f"{path}[{idx}]"
            if find_none(item, subpath):
                found = True

    return found

def test_topofiles_exist():
    # check if the topology files exist
    date = "2025-08-19"
    ytopos_urls = {}
    bucket_root = "https://storage.googleapis.com/archive-measurement-lab/"
    prefix = f"wehe/ytopologies/{date}/"

    r = requests.get(bucket_root, params={"prefix": prefix, "delimiter": "/"})
    if r.status_code == 200:
        content = bs4.BeautifulSoup(r.text, "xml")
        for key in content.find_all("Key"):
          m = re.search(rf"{re.escape(prefix)}ytopologies-(.*?)-(.*?)-.*\.json$", key.getText())
          if m:
              ytopos_urls['/'.join(m.groups())] = urllib.parse.urljoin(bucket_root, key.getText())
    assert len(ytopos_urls.keys()) > 0, "No Y-topology files found for the date {}".format(date)
    
    print("ytopos_urls:", ytopos_urls)
    return ytopos_urls
    
def test_gcs():
    # run the download of Y topologies to see if it crashes
    date = "2025-08-19"
    
    topos_urls = test_topofiles_exist()
    for subnet, gcs_url in topos_urls.items():
      
      data = requests.get(gcs_url).json()
      try:
        print(f"Client info for subnet {subnet}: 'ASN': {data['ASN']}, 'ASName': {data['ASName']}, 'subnet': {data['subnet']}")
      except Exception as e:
        print(f"Error processing data for subnet {subnet}: {e}")
        continue
      
      assert data is not None, f"Data for {subnet} is None"
      