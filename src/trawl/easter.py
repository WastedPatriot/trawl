"""Things that are not a scan."""

from rich.console import Console

# Printed by a flag that isn't in --help. On purpose.
CATCH = r"""
        .'.
       /   `>
  ><(((º>
       \   '>
        `.'

catch of the day
a mullet, slightly judgemental
it saw the open port. the report is still yours.
"""


def show_catch(console: Console) -> None:
    console.print(CATCH, markup=False, highlight=False)
