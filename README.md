# scripts
A collection of short programs written for Matasano Crypto Challenges and Introduction to Criptography. The Crypto challenges are numerated by the problem set. The first task of Introduction to Cryptography involved breaking OTP with reuse with only one repeated use with arbritary message sizes.

Tasks one and two were lost before I knew better than keep my git server on my computer. Some easier tasks were skipped(try different weird primes for RSA and see the modulus be strange, for instance). Also I can't seem to find my last two questions of pset 6. I will redo them quickly for completeness Sake.

The OTP reuse breaker is a non-deterministic traversal of an automata, in which the nodes are states of a trie built using a dictionary. Special transitions were placed to account for punctuation. The traversal favors small words so that the dictionary can be trimmed more easily(by removing the less common words with less than 3 letters, speed and accuracy greatly improved).

I will proably try to maintain this repository as a learning tool for people interested in criptography struggling to find implementations of some more tricky algorithms(That's how I felt with a more generic otp breaker before). Keep in mind that those are some of my early work, and that the performance as well as core readability may be far from ideal.
