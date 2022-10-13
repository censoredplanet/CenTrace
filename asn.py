import os
import re
import pyasn
import pathlib
from typing import NamedTuple, Iterator, List

def _read_routeviews_file(path: str) -> Iterator[str]:
    with open(path) as rv_file:
        for line in rv_file:
            yield line.strip()


def _parse_asn_db(f: Iterator[str]) -> pyasn.pyasn:
  """Returns a pyasn db from a routeview file.
  Args:
    f: an routeview file Iterator
  Returns:
    pyasn database object
  """
  # CAIDA file lines are stored in the format
  # 1.0.0.0\t24\t13335
  # but pyasn wants lines in the format
  # 1.0.0.0/24\t13335
  formatted_lines = map(
      lambda line: re.sub(r"(.*)\t(.*)\t(.*)", r"\1/\2\t\3", line), f)
  as_str = "\n".join(formatted_lines)
  del formatted_lines
  asn_db = pyasn.pyasn(None, ipasn_string=as_str, as_names_file=ASNAMES_FILEPATH)
  return asn_db

def lookup(ASNDB, ip):
  if ip is None or len(ip) == 0:
    return None
  asn = ASNDB.lookup(ip)[0]
  if asn == None or asn == "None":
      return None
  return f"{asn}, {ASNDB.get_as_name(asn)}"

def init(routeviews_file, asnames_file):
  global ROUTEVIEWS_FILEPATH
  global ASNAMES_FILEPATH

  ROUTEVIEWS_FILEPATH = routeviews_file
  ASNAMES_FILEPATH = asnames_file
  ASNDB = _parse_asn_db(_read_routeviews_file(ROUTEVIEWS_FILEPATH))
  return ASNDB

