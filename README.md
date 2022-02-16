# Forgiva Server

## INTRODUCTION

```
      .-" L_    FORGIVA Server
 ;`, /   ( o\   The new-age password manager.
 \  ;    `, /
 ;_/"`.__.-"

```

Forgiva Server is backend component for Forgiva Enterprise, it is responsible to calculate
metadatas provided and return accurate results complying Forgiva reference documentation.

Please refer to the Algorithm section at.

https://github.com/Sceptive/forgiva/blob/ea7e942e7523a301f89ecda6275f243b1d84bf05/README.md


## BUILDING

You can either;

 - create release distributions of of Forgiva Server binaries with,

```
$ ./build.sh release
```

which will be building forgiva_server-<version-cp-release.tar.xz inside current directory 
containing binaries for both Windows and Linux environments

 - create local builds with,

```
$ ./build.sh
```

which will be building local binary at build/local/forgiva_server

 - create container images with

```
$ ./build.sh image
```

which will be building forgiva_server:<version> image for Docker containers.


## TESTING


### Single test

You can test simply launched instance by using local test file;

```
$ cat ../etc/test.json | curl  -d @- http://localhost:3000/generate
```

### Sanity test

You can launch a sanity test to test whether all functions running properly with

```
$ ./build.sh test
```

or simply adding "-t" parameter to the Forgiva Server binary.

A simple result will be like below


```
      .-" L_    FORGIVA Server
 ;`, /   ( o\   The new-age password manager.
 \  ;    `, /
 ;_/"`.__.-"

[*] Testing Simple Hash & Encryption ...
[+] Tested camellia-128-cbc encryption algorithm SUCCESSFULLY
[+] Tested camellia-192-cbc encryption algorithm SUCCESSFULLY
[+] Tested camellia-256-cbc encryption algorithm SUCCESSFULLY
[+] Tested cast5-cbc encryption algorithm SUCCESSFULLY
[+] Tested bf-cbc encryption algorithm SUCCESSFULLY
[+] Tested aes-128-cbc encryption algorithm SUCCESSFULLY
[+] Tested aes-192-cbc encryption algorithm SUCCESSFULLY
[+] Tested aes-256-cbc encryption algorithm SUCCESSFULLY
[+] Tested sha512 hash algorithm  SUCCESSFULLY
[+] Tested sha384 hash algorithm  SUCCESSFULLY
[+] Tested sha256 hash algorithm  SUCCESSFULLY
[+] Tested sha224 hash algorithm  SUCCESSFULLY
[+] Tested sha1 hash algorithm  SUCCESSFULLY
[+] Tested sha hash algorithm  SUCCESSFULLY
[+] Tested md5 hash algorithm  SUCCESSFULLY
[+] Tested md4 hash algorithm  SUCCESSFULLY
[+] Tested ripemd160 hash algorithm  SUCCESSFULLY
[+] Tested argon2d algorithm  SUCCESSFULLY
[+] Simple Hash & Encryption --- SUCCESFULLY --- (0.98281ms)
[*] Testing Generation of passwords ...
[*] Testing for facebook.com / bill.gates@microsoft.com / 1970-01-01 / Ape  on complexity level 1...
[*] OK  yp6Y*G_xDLaSPM7W ( 797036592a475f78444c6153504d375700 )  (Ape)
[*] Testing for +SCRYPT facebook.com / bill.gates@microsoft.com / 1970-01-01 / Ape  on complexity level 1...
[*] OK +SCRYPT FktgMdZMi90*nVyz ( 466b74674d645a4d6939302a6e56797a00 )  (Ape)
[*] Testing for +ARGON2 facebook.com / bill.gates@microsoft.com / 1970-01-01 / Ape  on complexity level 1...
[*] OK +ARGON2 InBWJFbjB98Szl6Z ( 496e42574a46626a423938537a6c365a00 )  (Ape)
[*] Testing for facebook.com / root / 1970-01-01 / Bat  on complexity level 2...
[*] OK  UD$_+rh.F5vP@AjI ( 5544245f2b72682e4635765040416a4900 )  (Bat)
[*] Testing for +SCRYPT facebook.com / root / 1970-01-01 / Bat  on complexity level 2...
[*] OK +SCRYPT 5K"=;l$g38l-ft(= ( 354b223d3b6c246733386c2d6674283d00 )  (Bat)
[*] Testing for +ARGON2 facebook.com / root / 1970-01-01 / Bat  on complexity level 2...
[*] OK +ARGON2 eS\Sw5sUJ8hOx0k0 ( 65535c53773573554a38684f78306b3000 )  (Bat)
[*] Testing for facebook.com / k3ym4k3r / 1970-01-01 / Bear  on complexity level 3...
[*] OK  O\vSQ2QAzgYI(LU9 ( 4f5c7653513251417a675949284c553900 )  (Bear)
[*] Testing for +SCRYPT facebook.com / k3ym4k3r / 1970-01-01 / Bear  on complexity level 3...
[*] OK +SCRYPT Xzyj|@&t&c{iM4TY ( 587a796a7c40267426637b694d34545900 )  (Bear)
[*] Testing for +ARGON2 facebook.com / k3ym4k3r / 1970-01-01 / Bear  on complexity level 3...
[*] OK +ARGON2 qs/TyWI\/18Jywyt ( 71732f547957495c2f31384a7977797400 )  (Bear)
[*] Testing for facebook.com / scr1ptk1dd1e / 1970-01-01 / Whale  on complexity level 1...
[*] OK  decZgSt2/GiPQFAW ( 6465635a675374322f4769505146415700 )  (Whale)
[*] Testing for +SCRYPT facebook.com / scr1ptk1dd1e / 1970-01-01 / Whale  on complexity level 1...
[*] OK +SCRYPT Icu9.cHjYCDs3Mai ( 496375392e63486a59434473334d616900 )  (Whale)
[*] Testing for +ARGON2 facebook.com / scr1ptk1dd1e / 1970-01-01 / Whale  on complexity level 1...
[*] OK +ARGON2 Pe3p1yfmjMV5EY8e ( 506533703179666d6a4d56354559386500 )  (Whale)
[*] Testing for microsoft.com / toor / 1970-01-01 / Crow  on complexity level 2...
[*] OK  M1EsXm@6Ig)pxmq3 ( 4d314573586d403649672970786d713300 )  (Crow)
[*] Testing for +SCRYPT microsoft.com / toor / 1970-01-01 / Crow  on complexity level 2...
[*] OK +SCRYPT >QT*M6M1evsF|mG( ( 3e51542a4d364d31657673467c6d472800 )  (Crow)
[*] Testing for +ARGON2 microsoft.com / toor / 1970-01-01 / Crow  on complexity level 2...
[*] OK +ARGON2 */Il<7fldN-386S\ ( 2a2f496c3c37666c644e2d333836535c00 )  (Crow)
[*] Testing for 192.168.0.1 / root / 1970-01-01 / Dog  on complexity level 3...
[*] OK  ,7m#JzlMox\4IJg* ( 2c376d234a7a6c4d6f785c34494a672a00 )  (Dog)
[*] Testing for +SCRYPT 192.168.0.1 / root / 1970-01-01 / Dog  on complexity level 3...
[*] OK +SCRYPT I9¢2!|\@ZlqNvU% ( 4939c2a232217c5c405a6c714e76552500 )  (Dog)
[*] Testing for +ARGON2 192.168.0.1 / root / 1970-01-01 / Dog  on complexity level 3...
[*] OK +ARGON2 T;,_)V8.CoIf*fW8 ( 543b2c5f2956382e436f49662a66573800 )  (Dog)
[*] Testing for 10.0.0.2:22 / root / 1970-01-01 / Duck  on complexity level 1...
[*] OK  d@V*67Pei6F9n1,K ( 6440562a36375065693646396e312c4b00 )  (Duck)
[*] Testing for +SCRYPT 10.0.0.2:22 / root / 1970-01-01 / Duck  on complexity level 1...
[*] OK +SCRYPT 4PWBZQ3ulYet_zpT ( 345057425a5133756c5965745f7a705400 )  (Duck)
[*] Testing for +ARGON2 10.0.0.2:22 / root / 1970-01-01 / Duck  on complexity level 1...
[*] OK +ARGON2 udoG@joA.9LdsUDI ( 75646f47406a6f412e394c647355444900 )  (Duck)
[*] Testing for 10.0.0.2:22 / k3ym4k3r / 1970-01-01 / Cat  on complexity level 2...
[*] OK  xC_WVn/SS_.aw8); ( 78435f57566e2f53535f2e617738293b00 )  (Cat)
[*] Testing for +SCRYPT 10.0.0.2:22 / k3ym4k3r / 1970-01-01 / Cat  on complexity level 2...
[*] OK +SCRYPT \bO#r>pFsE%0w>1D ( 5c624f23723e704673452530773e314400 )  (Cat)
[*] Testing for +ARGON2 10.0.0.2:22 / k3ym4k3r / 1970-01-01 / Cat  on complexity level 2...
[*] OK +ARGON2 wlbMn8|\o"gaRv83 ( 776c624d6e387c5c6f2267615276383300 )  (Cat)
[*] Testing for 10.0.0.2:22 / toor / 1970-01-01 / Wasp  on complexity level 3...
[*] OK  TSJX+&_3~.C@;Sha ( 54534a582b265f337e2e43403b53686100 )  (Wasp)
[*] Testing for +SCRYPT 10.0.0.2:22 / toor / 1970-01-01 / Wasp  on complexity level 3...
[*] OK +SCRYPT 3+%A6N0e7pNEQv98 ( 332b2541364e306537704e455176393800 )  (Wasp)
[*] Testing for +ARGON2 10.0.0.2:22 / toor / 1970-01-01 / Wasp  on complexity level 3...
[*] OK +ARGON2 *}{1@uS0B1YrT2ni ( 2a7d7b31407553304231597254326e6900 )  (Wasp)
[+] Generation of passwords --- SUCCESFULLY --- (0:11:42.101ms)
```


### Fuzzing 

Alternatively you can stress test with fuzzing using AFL; 

To launch AFL;

1. Download and install afl

```
$ wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
$ make && make install
```

2. In the build directory configure cmake to use AFL binaries

```
$ CC=/usr/local/bin/afl-gcc CXX=/usr/local/bin/afl-g++ cmake -DCMAKE_BUILD_TYPE=Debug ..
$ make -j 8
```

(It's important to clear all the cmake cache files)

3. Create in and out directories and copy etc/test.json to in directory and run afl-fuzz like:

```
$ mkdir in && mkdir out
$ afl-fuzz -i in -o out -t 20000  -- ./forgiva_server -s
```

### Benchmarking

You can test for loads with 'hey'

```
$ sudo apt install golang-go
$ go get -u github.com/rakyll/hey
$ hey -D ../etc/test.json -t 0 http://localhost:3000/generate
```

### Valgrind Test

You can launch valgrind to ensure memory leaks and various problems.

```
$ valgrind --leak-check=full ./forgiva_server
```

## Contacts

You can reach main developer Harun Esur at 

```
      root [at] sceptive [dot] com 
```

or

```
      harun.esur [at] sceptive [dot] com 
```