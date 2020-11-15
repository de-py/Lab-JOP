# Lab-JOP
This lab covered jump oriented programming and utilized the jop rocket to find gadgets. These gadgets were then used to bypass DEP.

JOP is different from ROP in that you use a dispatch table and jop gadgets to loop through a set of instructions. The instructions do not have to be from the stack to execute so they do not impact the stack directly. One added complexity with this lab was utilizing xor to simulate the handling of null bytes, even though the stack did allow for nullbytes at the location the payload was used. So every address on the stack for VirtualProtect was ran through a set of XOR instructions, albeit just for show.
