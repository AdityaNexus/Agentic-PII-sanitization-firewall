from typing import Dict

class PIIVault:
    def __init__(self):
        self.mapping : Dict[str,str] = {}
    
    def store(self,token:str,value:str)->None:
        self.mapping[token] = value
    
    def restore(self, text: str) -> str:
        restored = text 

        for token, value in self.mapping.items():
            restored = restored.replace(token, value)

        return restored

    def get_mapping(self)->Dict[str,str]:
        return self.mapping.copy()