from dataclasses import dataclass
from typing import Callable, List, Optional

@dataclass
class MenuItem:
    key: str
    title: str
    handler: Callable  
    help: str = ""

class Menu:
    def __init__(self, title: str, items: List[MenuItem]):
        self.title = title
        self.items = items

    def run(self, ctx):
        while True:
            print("\n" + self.title)
            print("-" * len(self.title))
            for it in self.items:
                print(f"{it.key}) {it.title}")
            choice = input("Vyber: ").strip()

            item = self._find_item(choice)
            if not item:
                print("Neplatná voľba.")
                continue

            if item.key == "0":
                break

            try:
                item.handler(ctx)
            except KeyboardInterrupt:
                print("\nPrerušené používateľom (Ctrl+C).")
            except Exception as e:
                print(f"\n[CHYBA] Modul spadol: {e}")

    def _find_item(self, key: str) -> Optional[MenuItem]:
        for it in self.items:
            if it.key == key:
                return it
        return None
