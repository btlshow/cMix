# cMix
Mixing with Minimal Real-Time Asymmetric Cryptographic Operations.    
This project implements the cMix mixnet basic specifications，and has the real communication over sockets.

Reference：cMix：Mixing with Minimal Real-Time Asymmetric Cryptographic Operations.         
          David Chaum,Debajyuti Das,Farid Javani,Aniket Kate,Anna Krasnova,Joeri De Ruiter,and Alan T.Sherman
          
These two source code files were writen by btlshow            
School of Cyber Engineering in XiDian University

Operating environment：Ubuntu 18.04

testmixnode.c：      
MSGNUM：the number of CMixclient         
main function parameter：      
（1）next mixnode’s ip address  
（2）which place is this node in the network        
（3）which kind is this mixnode  1：the first one 2:the middle 3:the last one      
for example: ./Mixnode 192.168.1.40 4 3

# Note:
you need to use the Multiprecision Integer and Rational Arithmetic C Library(MIRACL)and get it here:https://libraries.docs.miracl.com/
