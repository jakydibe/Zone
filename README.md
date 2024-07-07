This is a Metamorphing Engine.

At this moment the only morphing techniques included are 
    1) equal code subsitution (Of course bigger instructions than originals are supported)
    2) junk code insertion

I spent so much time trying to make it running because a single byte increase in an instruction results in 
all references broken so the code is mainly patching all references.

Also there is a file (increase_text.py) which increases the .text section of an executable
I found that there are not tools that permit this operation so i decided to do it


BOTH THE METAMORPHIC ENGINE AND THE .TEXT INCREASER ONLY WORKS ON CERTAIN VERY EASY EXECUTABLE (such as a simple hello_worlc. compiled with cl.exe)
