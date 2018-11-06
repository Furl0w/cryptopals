## Taking the cryptopals challenges in go

Learning go is part of this repo, I don't intend to go back on the challenge if I realize there was a cleaner way to do it.
If you are looking for a clean solution of cryptopals in go I advice you to look the solutions from Filippo Valsorda.

__27/09__ : set 1 done, key of number 6 is off by one character (i instead of n, could probably do a better scoring), ECB decryption is slightly off as well with a few blocks non existent added at the end but the message is clearly visible

__09/10__ : set 2 done, nothing too hard and no result broken this time.
Go syntax is becoming cleaner but still a lot to work on. I left in comments the reasoning behind the inputs I used for the ECB cut-and-paste and CBC bitflipping.

__21/10__ : set 3 done, good way to revise bitwise operations. I did rewrite the 2_15 when I realized I had it wrong and I needed it for the CBC padding oracle. I skipped the 3_19 mainly because it didn't teach anything (solving it statistically is 3_20) beside guessing. I might go back to finish it if I'm in the mood.
Even though I didn't include it in the repo I validated my implementation of MT19937 against the native one in C++.

__06/11__ : set 4 done, easier than set 3 as stated by the writers. I used the sha1 and md4 implementations from the crypto library directly and just rewrote the reset function to inject the initial values for the length extension attacks.
I made a small (very bad) server for the 31 and 32 and ended up skipping the 31 mostly because I have no patience and 50ms is long, and because it's just an easier version of 32. I think I could have detected the good byte using difference from average request time but it was constantly breaking with small timing leaks so I went with a dumber (and way slower) method.
I did not push it past 2ms of leak every round.
