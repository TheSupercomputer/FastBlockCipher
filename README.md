# FastBlockCipher
A fast cipher based on blocks for fast multi thread encryption of files.

## Watch out
This is more like a PoC than a safe cipher algorithm, until proven other.
It was primarily intended to practice file I/O and multi threading on an project which is not purely theoretically and therefore FastBlockCipher should be handled as such a side project with no real intention. At least for now.
It might grow in future, if it become useful but. I doubt it will.

Nevertheless it will get some feature updates on an irregular basis.

cipher.cpp and cipher.hpp do contain the cipher class.
main.cpp has an example implementation in it. 

- [X] can cipher large files
- [ ] can cipher files that do not fit in half of the memory
- [ ] add useful comments to the source code
