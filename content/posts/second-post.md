---
title: "Second Post"
date: 2023-03-08T13:36:15Z
draft: false
---


## Cryptography:
### Challenge name : Baby-Crypto 
```Write-Up:```
#### 1. Given code:
```
from secret import FLAG


lookup = {'A':'aaaaa', 'B':'aaaab', 'C':'aaaba', 'D':'aaabb', 'E':'aabaa', 
'F':'aabab', 'G':'aabba', 'H':'aabbb', 'I':'abaaa', 'J':'abaab', 
'K':'ababa', 'L':'ababb', 'M':'abbaa', 'N':'abbab', 'O':'abbba', 
'P':'abbbb', 'Q':'baaaa', 'R':'baaab', 'S':'baaba', 'T':'baabb', 
'U':'babaa', 'V':'babab', 'W':'babba', 'X':'babbb', 'Y':'bbaaa', 'Z':'bbaab' , '_': 'bbbbb'} 

 
def encrypt(message): 
    cipher = '' 
    for letter in message: 
        if(letter != ' '): 
            cipher += lookup[letter] 
        else: 
            cipher += ' '
  
    return cipher 
   

if __name__=='__main__':
	
    cipher=encrypt(FLAG)

    print('Here take your cipher text: ',cipher)
```    
### 2. So the basic logic game lies in lookup.

### python code to solve it.

#### with the given code we reverse the keys and values of the lookup dictionary.
```
reverse = dict(map(reversed,lookup.items()))

reverse = {'aaaaa': 'A', 'aaaab': 'B', 'aaaba': 'C', 'aaabb': 'D', 'aabaa': 'E', 'aabab': 'F', 
'aabba': 'G', 'aabbb': 'H', 'abaaa': 'I', 'abaab': 'J', 'ababa': 'K', 'ababb': 'L', 'abbaa': 'M', 
 'abbab': 'N', 'abbba': 'O', 'abbbb': 'P', 'baaaa': 'Q', 'baaab': 'R', 'baaba': 'S', 
 'baabb': 'T', 'babaa': 'U', 'babab': 'V', 'babba': 'W', 'babbb': 'X', 
  'bbaaa': 'Y', 'bbaab': 'Z', 'bbbbb': '_'}



str3 = list()
for i in range(0,115,5):
	str3.append(str1[i:i+4])
#str3 = ['babba', 'aabaa', 'ababb', 'aaaba', 'abbba', 'abbaa', 'aabaa', 'bbbbb', 'baabb', 'abbba', 'bbbbb',
        'aaaba', 'baaab', 'bbaaa', 'baabb', 'abbbb', 'abbba', 'bbbbb', 'babba', 'abbba', 'baaab', 'ababb', 'aaabb']
for i in str3:
	print(reverse[i],end = '')

# WELCOME_TO_CRYTPO_WORLD

