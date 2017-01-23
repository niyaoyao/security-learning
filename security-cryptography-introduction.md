title: Introduction to Information Security with Cryptography
comments: true
date: 2017/01/23
tags: 
- Cryptography
categories: 
- Security
---

Introduction to Information Security with Cryptography

Chap 1第一章  绪论 (Introduction)
    1.1  通讯安全 (Communication Security)
      1.1.1  移位加密法 (Shift Cipher)
      1.1.2  替换加密法 (Substitution Cipher)
      1.1.3  映射加密法 (Affine Cipher)
      1.1.4  维吉尼亚加密法 (Vigenere Cipher)
      1.1.5  山丘加密法 (Hill Cipher)
      1.1.6  排列加密法 (Permutation Cipher)
      1.1.7  串流加密法 (Stream Cipher)与区块加密法(Block Cipher)
  1.2  公开密码系统与对称密码系统 Public Key and Symmetric Cryptosystem
    1.2.1  模代数运算 (Modular arithmetic)
    1.2.2  因式分解难题 (Factoring Difficult Problem)
    1.2.3  楕圆曲线问题( Elliptic Curve Problem)
  1.3  密码分析 (Cryptanalysis)
      1.3.1  暴力攻击法 (Brute-Force Attack)
      1.3.2  己知明文攻击法 (Known  Plaintext Attack)
      1.3.3  绝对安全 (Absolutely Safe)
  1.4  实作与练习 (Exercise and Practical)

Chap 2第二章  古典密码学码系统 (Classical Cryptography)
    2.1  西泽挪移密码 (Caesar Shift Cipher)
    2.2  仿射密码 (Affine Cipher)
    2.3  单套字母替代法
    2.4 Vige nere 密码 (Polyalphabetic Substitution)
    2.5 单次密码簿(One time pad)
    2.6 Enigma 密码机 (Enigma)

Chap 3第三章 基础数论 (Foundation of Number Theory)
      3.1 模运算(Modulo Operation)
3.2 同余(Congruence)
3.3 辗转相除法 (Method of Successive Division)
3.4 原根 (Primitive Root)
3.5 二次剩余 (Quadratic Residue)
3.6 Galois Field
3.7 质数理论 (Prime number theory)
3.8 Lagrange定理与费马小定理 (Lagrange and Fermat's Little Theorem)
3.9 连分数 (Continue Fracted Number) 
Chap 4第四章  讯息理论(Information Theory)
      4.1 机率 (Probability)
4.2 完美秘密 (Perfect Secrecy)
4.3 熵(Entropy)

Chap 5第五章  公开金钥密码系统(Public-Key Cryptography)
    5.1  RSA Cryptosystem
    5.2  ElGamal Cryptosystem
    5.3  Elliptic Curve Cryptosystem
    5.4  Merkle-Hellman Knapsack system
    5.5  McEliece System
Chap 6第六章  公开金钥密码标准 (Public Key Cryptosystem Standards)
    6.1  Password-based Cryptography Standard
    6.2  Diffie-Hellman Key Agreement Standard
Chap 7第七章  数位签章 ( Digital Signature)
    7.1  RSA Digital Signature
    7.2  ElGamal Digital Signature
    7.3 DSA Digital Signature
	7.3 Schnoor Digital Signature
	7.4 Nyberg-Rueppel Digital Signature
	7.5 Hash Function
Chap 8第八章  质数与大整数算术 (Prime Number and Large Integer Arithmetic)
	8.1 Large Integer in Addition, Subtraction and multiplication
	8.2 Large Integer in Division
	8.3 Montgomery Algorithm
	8.4 Modulus in Exponential operation
	8.5 Miller-Rabin Prime Number Testing
	8.6 Agrawal-Kayal-Saxena Algorithm
	8.7 Some Software Packages
Chap 9 第九章  金钥交换与密码认证协议 (Key Agreement and Password Authentication)
	9.1 Encryption Key Exchange
	9.2 Key Agreement and Exchange
	9.3 Simple Authentication and Key Agreement (SAKA)
	9.4 Key Agreement and Password Authentication (KAPA)
	9.5 Known Attacks in SAKA
	9.6 Known Attack in KAPA
Chap 10 第十章  椭圆曲线密码系统 (Elliptic Curve Cryptosystem)
	10.1 Elliptic Curve
	10.2 Elliptic Curve in Modulus p
	10.3 ECC Diffie-Hellman
	10.4 Parallel Pollard Rho Method
Chap 11 第十一章 量子密码系统 (Quantum Cryptography)
	11.1 Quantum Experiment
	11.2 Quantum Computer
	11.3 Quantum Key Distribution Problem
	11.4 Shor Algorithm in Quantum Cryptanalysis


新增实用技巧篇 (这个章节，是完全利用到密码技术、crack me、及Windows API core，可以说是前面所学到的，完全会在这里派上用场)

Chap 12 第十二章 密码学在软件安全中的应用 ( The Cryptography applied in Software Security)
	12.1 Introduction to Kernel32 API in Windows serials products 
	12.2 Kernel32 API地址定位 (exploit, virus / Hash Cipher)
	12.3 文件校验, 内存校验等 (单向散列: CRC,MD5等)
	12.4 SMC(任意Cipher)
	12.5 运用 RSA1024 防止注册机(key generator) 的三两事
	12.6 Exercise 