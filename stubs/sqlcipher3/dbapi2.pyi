import sqlite3
from typing import Any, Callable, Optional, Sequence, Type

connect: Callable[..., sqlite3.Connection]
Connection = sqlite3.Connection
Cursor = sqlite3.Cursor
Row = sqlite3.Row
DatabaseError = sqlite3.DatabaseError
OperationalError = sqlite3.OperationalError
IntegrityError = sqlite3.IntegrityError
Error = sqlite3.Error
Warning = sqlite3.Warning
InterfaceError = sqlite3.InterfaceError
DataError = sqlite3.DataError
InternalError = sqlite3.InternalError
ProgrammingError = sqlite3.ProgrammingError
NotSupportedError = sqlite3.NotSupportedError
