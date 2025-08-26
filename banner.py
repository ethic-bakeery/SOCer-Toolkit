# banner.py
import os
import sys

def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM") not in (None, "dumb")

def colorize(s: str, fg: int = 82) -> str:
    """Add ANSI color (default = green 82)."""
    return f"\033[38;5;{fg}m{s}\033[0m" if supports_color() else s

def print_banner():
    big_s = r"""
  .--.--.                                               
 /  /    '.                                             
|  :  /`. /     ,---.                           __  ,-. 
;  |  |--`     '   ,'\                        ,' ,'/ /| 
|  :  ;_      /   /   |    ,---.      ,---.   '  | |' | 
 \  \    `.  .   ; ,. :   /     \    /     \  |  |   ,' 
  `----.   \ '   | |: :  /    / '   /    /  | '  :  /   
  __ \  \  | '   | .; : .    ' /   .    ' / | |  | '    
 /  /`--'  / |   :    | '   ; :__  '   ;   /| ;  : |    
'--'.     /   \   \  /  '   | '.'| '   |  / | |  , ;    
  `--'---'     `----'   |   :    : |   :    |  ---'     
                         \   \  /   \   \  /            
                          `----'     `----'             
"""
    small_ocer = r"""
   ooo   ccc   eee   rrr
  o   o c     e     r  r
  o   o c     eee   rrr 
  o   o c     e     r r 
   ooo   ccc   eee   r  r
"""

    # Print with different colors
    print(colorize(big_s, 39))      # Big "S" in blue
    print(colorize(small_ocer, 208))  # "ocer" in orange

if __name__ == "__main__":
    print_banner()