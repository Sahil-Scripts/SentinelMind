# Compatibility bridge so old code like `from models import Event` still works.
from schemas.models import *  # re-export everything
