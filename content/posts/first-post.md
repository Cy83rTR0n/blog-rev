---
title: "First Post"
date: 2023-03-08T11:10:20Z
draft: true
---
## we are given the following file 
```
# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.17 (default, Sep 30 2020, 13:38:04) 
# [GCC 7.5.0]
# Embedded file name: reverseme.py
# Compiled at: 2021-09-04 11:21:21
import numpy as np
flag = 'TamilCTF{this_one_is_a_liability_dont_fall_for_it}'
np.random.seed(369)
data = np.array([ ord(c) for c in flag ])
extra = np.random.randint(1, 5, len(flag))
product = np.multiply(data, extra)
temp1 = [ x for x in data ]
temp2 = [ ord(x) for x in 'dondaVSclb' * 5 ]
c = [ temp1[i] ^ temp2[i] for i in range(len(temp1)) ]
flagdata = ('').join(hex(x)[2:].zfill(2) for x in c)
real_flag = '300e030d0d1507251700361a3a0127662120093d551c311029330c53022e1d3028541315363c5e3d063d0b250a090c52021f'
```

## we are trying to analyze the python file by going through the same steps.

```py
import numpy as np
flag = 'TamilCTF{this_one_is_a_liability_dont_fall_for_it}'
```

- The above is actually a fake flag 

- But we will use it for analysis purpose.

```py
np.random.seed(369)

data = np.array([ord(c) for c in flag ])

print('data :',data)
```

- random function which is used as the seed here is not actually random, if we every time repeat lines 8 and 9 we will get the same data array.

```py
extra = np.random.randint(1,5,len(flag))
print('extra :',extra)
```

- similarly the above also we will get everytime the same array if we follow lines 8,9,17.


```py 
product = np.multiply(data,extra)

print('product :',product) 

temp1 = [x for x in data ]

print('temp1:',temp1)

temp2 = [ord(x) for x in 'dondaVSclb' * 5]

print('temp2',temp2)

c = [ temp1[i] ^ temp2[i] for i in range(len(temp1)) ]

print('c:',c)

flagdata = ('').join(hex(x)[2:].zfill(2) for x in c)

print('flagdata :',flag)

```

- here in the lines 39 and 40 we see that first the items in c are converted to hex that is 48 to 0x30 and then we neglect '0x' and then they are joined together. 

- now upto this part whatever we did was actually for analysing the code.

- exploit starts from here 

```py

real_flag = '300e030d0d1507251700361a3a0127662120093d551c311029330c53022e1d3028541315363c5e3d063d0b250a090c52021f'

```


- above given is the final result of the actual flag.

- let's reverse it

```py
real = list()

for i in range(0,100,2):

  real.append(real_flag[i:i+2]) 

print('real:',real)
```

- We get the required array with elements but now we need to get the decimal output for our hex numbers.

```py
real_2 = list()

for i in real:

  real_2.append(int(i,16)) 

print('real_2',real_2)
```
- our temp2 array remains the same 

```py
print('temp2 :',temp2)

temp3 = list()
temp3 = [temp2[i] ^ real_2[i] for i in range(len(temp2))]

temp4 = list()
for i in temp3:

  temp4.append(chr(i))

print(''.join(temp4))
```

# Flag

`TamilCTF{bRuTeF0rCe_1s_tHe_0nLy_F0rCe_2_bReAk__1n}`







