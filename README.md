Taking the cryptopals challenges in go

Learning go is part of this repo, I don't intend to go back on the challenge if I realize there was a cleaner way to do it.
If you are looking for a clean solution of cryptopals in go I advice you to look the solutions from Filippo Valsorda.

27/09 : set 1 done, key of number 6 is off by one character (i instead of n, could probably do a better scoring), ECB decryption is slightly off as well with a few blocks non existent added at the end but the message is clearly visible

09/10 : set 2 done, nothing too hard and no result broken this time.
Go syntax is becoming cleaner but still a lot to work on. I left in comments the reasoning behind the inputs I used for the ECB cut-and-paste and CBC bitflipping.