# Strategy

Before diving within Quokka, let's try to understand how we could solve the problem on paper.

## Steps
1. Identify a function using the user table
2. Find a data reference to the table
3. Identify the table boundaries
4. Read one entry
5. Repeat until the end of the table


## Step 1: Identify a function using the user table

For this, we have no choice but to read the manual.

The `getpwuid` function is a good candidate, look at the manual below:

```text
The  getpwuid()  function  returns a pointer to a structure containing the
broken-out fields of the record in the password database that matches  the
user ID uid.
```

Lets select the function:

```python
# WARNING: Not working

from quokka import Function
function: Function = bionic.get_function("getpwuid")

assert function.name == "getpwuid" # Raises an error
```

The previous snippet generates an error. Indeed, the `function` selected is not `getpwuid` but `j_getpwuid`.
However, the signature of the `get_function` method has an additional parameter:

```python
Program.get_function(name: 'str', approximative: 'bool' = True, normal: 'bool' = False) -> 'quokka.Function'
```

Thus, the correct code to select the `getpwuid` function is:

```python
getpwuid: Function = bionic.get_function("getpwuid", approximative=False)
assert getpwuid.name == "getpwuid" # Correct
```

## Step 2: Find the data reference to the table

We know that the `getpwuid` functions must use the user mapping we are searching. So, a (data) reference towards the 
table must exist within the function. Lets explore them:

```python
for data in getpwuid.data_references:
    print(f"{data.name} ({data.type}) at 0x{data.address:x}")
```

```shell
None (DataType.DOUBLE_WORD) at 0x1d024
_ZL11android_ids (DataType.DOUBLE_WORD) at 0x8cda0
_ZL11android_ids (DataType.DOUBLE_WORD) at 0x8cda0
None (DataType.DOUBLE_WORD) at 0x8cda4
```
So the second and third reference in the function are towards the table we are looking for!

Let's find the beginning of our user table:

```python
from quokka import Data
user_table: Data = getpwuid.data_references[1]

print(f"{user_table.address=:x}")
# user_table.address=8cda0
```

## Step 3: Identify the table boundaries

For this step, we are going to use an heuristic: 
* We know that the user table is contiguous in memory
* We know that there are no code-references to the middle of the table

So we are going to iterate the memory, starting at the first entry until an element as a code reference pointing 
towards it.

To find if an element has a code reference, there is a convenient accessor:

```python
data = bionic.get_data(address)
assert data.code_references != [], "Has code references"
```

So our loop to iterate _until_ the end of the table will look like this:

```python
from quokka.types import AddressT

address: AddressT
while True:
    data = bionic.get_data(address)
    if data.code_references:
        break
        
    ...
```

## Step 4: Read one entry

The structure of the table is as followed:
```c
struct android_id_info {
  const char name[17];
  unsigned aid;
};
```

To read this with Quokka:

```python
# Start with the first entry, using the read_string method
user_name = bionic.executable.read_string(user_table.value)
# cameraserver
```

And read the user ID too: it will be on the next DWORD:
```python
first_id = bionic.get_data(user_table.address + 0x4).value
# 1047
```

However, the snippet above works only if IDA found the data in the program. Otherwise, it will fail with the following
error:

```shell
ValueError: No data at offset 0x8cdbc
```

Another solution is to write this helper script:
```python
from quokka import Program
from quokka.types import AddressT, DataType

def read_userid(prog: Program, address: AddressT) -> int:
    """Read an user ID within the program at `address`"""
    return prog.executable.read_data(
        prog.addresser.file(address), DataType.DOUBLE_WORD
    )
```

## Step 5: Repeat until the end of the table

Now, we have every component of our script, let put it together within a loop:

```python hl_lines="9 10"
from quokka.types import AddressT

start: AddressT = user_table.address + 0x8
while True:
    data = bionic.get_data(start)
    if data.code_references:
        break

    user_name = bionic.executable.read_string(data.value)
    user_id = read_userid(bionic, data.address + 0x4)

    start += 0x8
```

