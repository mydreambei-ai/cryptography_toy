# Learning With Errors (LWE) - Regev Encryption Scheme

## 目录

- [简介](#简介)
- [数学预备知识](#数学预备知识)
  - [格（Lattice）](#格lattice)
  - [离散高斯分布](#离散高斯分布)
  - [模运算（Modular Arithmetic）](#模运算modular-arithmetic)
- [LWE 问题](#lwe-问题)
  - [定义](#定义)
  - [难度假设](#难度假设)
  - [搜索 LWE 和判定 LWE](#搜索-lwe-和判定-lwe)
- [Regev 加密方案](#regev-加密方案)
  - [密钥生成（Key Generation）](#密钥生成key-generation)
  - [加密（Encryption）](#加密encryption)
  - [解密（Decryption）](#解密decryption)
  - [正确性分析](#正确性分析)
- [安全性分析](#安全性分析)
  - [最坏情况到平均情况的归约](#最坏情况到平均情况的归约)
  - [抗量子攻击能力](#抗量子攻击能力)
- [参数选择](#参数选择)
- [优化与变种](#优化与变种)
- [应用场景](#应用场景)
- [参考文献](#参考文献)

## 简介

Learning With Errors (LWE) 是一个基于格理论的计算难题，由 Oded Regev 在 2005 年提出。LWE 问题的难度基于格中最短向量问题 (SVP) 和最近向量问题 (CVP) 的难解性，这些问题被认为即使在量子计算环境下也是难以解决的。基于 LWE 问题，Regev 提出了一种公钥加密方案，成为了后量子密码学的重要基石。

本文档详细介绍 LWE 问题的核心原理及基于 LWE 的 Regev 加密方案的实现细节。

## 数学预备知识

### 格（Lattice）

格是 n 维欧几里得空间中的离散加法子群。对于 n 维空间 $\mathbb{R}^n$，一个秩为 m 的格 $\mathcal{L}$ 可以表示为 m 个线性无关向量 $\{b_1, b_2, \ldots, b_m\}$ 的所有整数线性组合：

$$\mathcal{L} = \left\{\sum_{i=1}^{m} z_i b_i \mid z_i \in \mathbb{Z}\right\}$$

这些向量 $\{b_1, b_2, \ldots, b_m\}$ 构成格的一组基（basis）。

格理论中的两个核心计算问题是：
1. **最短向量问题 (SVP)**: 给定格的一组基，找到格中最短的非零向量
2. **最近向量问题 (CVP)**: 给定格的一组基和空间中的一个点，找到格中与该点最近的点

这两个问题在高维度下被认为是计算难题，LWE 的安全性就建立在这些问题的难解性上。

### 离散高斯分布

在 LWE 问题中，错误项通常遵循离散高斯分布。对于参数 σ > 0，整数 z 上的离散高斯分布 $D_{\mathbb{Z},\sigma}$ 定义为：

$$D_{\mathbb{Z},\sigma}(z) = \frac{1}{\sum_{z' \in \mathbb{Z}} e^{-\pi(z'/\sigma)^2}} \cdot e^{-\pi(z/\sigma)^2}$$

其中分母是归一化因子，确保概率总和为 1。该分布的方差约为 $\sigma^2 / (2\pi)$。

### 模运算（Modular Arithmetic）

模运算是在有限域上进行的运算。对于一个整数 q > 1，我们定义模 q 的整数环 $\mathbb{Z}_q = \mathbb{Z} / q\mathbb{Z} = \{0, 1, 2, \ldots, q-1\}$。

在 LWE 中，我们经常对向量进行模 q 运算，表示为 $\mathbf{v} \bmod q$，即对向量的每个分量进行模 q 运算。

## LWE 问题

### 定义

**学习带错误问题 (Learning With Errors, LWE)** 的形式化定义如下：

给定参数 n、q（通常是一个素数）和一个错误分布 $\chi$ 在 $\mathbb{Z}_q$ 上：

1. 选择一个秘密向量 $\mathbf{s} \in \mathbb{Z}_q^n$
2. 获得多个样本 $(\mathbf{a_i}, b_i)$，其中：
   - $\mathbf{a_i} \in \mathbb{Z}_q^n$ 是均匀随机选择的
   - $b_i = \langle \mathbf{a_i}, \mathbf{s} \rangle + e_i \bmod q$，其中 $e_i \in \mathbb{Z}_q$ 是从错误分布 $\chi$ 中抽取的
   - $\langle \mathbf{a_i}, \mathbf{s} \rangle$ 表示向量内积

LWE 问题就是在给定多个样本 $(\mathbf{a_i}, b_i)$ 的情况下，恢复秘密向量 $\mathbf{s}$。

### 难度假设

LWE 问题的难度基于以下假设：
- 当 n 足够大，q 是多项式大小，且错误分布 $\chi$ 适当选择时，没有多项式时间算法能够解决 LWE 问题
- 更强的是，Regev 证明了在最坏情况下，解决 LWE 问题至少与解决某些格问题一样困难

### 搜索 LWE 和判定 LWE

LWE 问题有两种形式：

1. **搜索 LWE**：给定样本 $(\mathbf{a_i}, b_i)$，找到秘密向量 $\mathbf{s}$

2. **判定 LWE**：区分真实 LWE 样本 $(\mathbf{a_i}, \langle \mathbf{a_i}, \mathbf{s} \rangle + e_i)$ 和均匀随机样本 $(\mathbf{a_i}, u_i)$，其中 $u_i$ 在 $\mathbb{Z}_q$ 上均匀随机

Regev 证明了这两个问题在多项式时间内是等价的，即如果能解决其中一个问题，就能解决另一个问题。

## Regev 加密方案

基于 LWE 问题，Regev 提出了一种公钥加密方案。该方案的安全性依赖于判定 LWE 问题的难解性。

### 密钥生成（Key Generation）

1. 选择参数：
   - 安全参数 n
   - 模数 q（通常是素数）
   - 错误分布 $\chi$（通常是参数为 $\alpha q$ 的离散高斯分布，其中 $\alpha$ 是一个小常数）
   - 明文空间 $\{0, 1\}$

2. 生成密钥：
   - 随机选择秘密向量 $\mathbf{s} \in \mathbb{Z}_q^n$
   - 生成 m 个随机向量 $\mathbf{a_1}, \mathbf{a_2}, \ldots, \mathbf{a_m} \in \mathbb{Z}_q^n$
   - 对每个 $\mathbf{a_i}$，计算 $b_i = \langle \mathbf{a_i}, \mathbf{s} \rangle + e_i \bmod q$，其中 $e_i$ 从错误分布 $\chi$ 中采样
   - 私钥：$\mathbf{s}$
   - 公钥：$(\mathbf{A}, \mathbf{b})$，其中 $\mathbf{A} = [\mathbf{a_1}, \mathbf{a_2}, \ldots, \mathbf{a_m}]^T$ 和 $\mathbf{b} = [b_1, b_2, \ldots, b_m]^T$

### 加密（Encryption）

为了加密一个比特 $\mu \in \{0, 1\}$：

1. 随机选择一个子集 $S \subseteq \{1, 2, \ldots, m\}$
2. 计算：
   - $\mathbf{a'} = \sum_{i \in S} \mathbf{a_i} \bmod q$
   - $b' = \sum_{i \in S} b_i + \mu \cdot \lfloor q/2 \rfloor \bmod q$
3. 密文是对 $(\mathbf{a'}, b')$

实际上，这相当于使用随机子集和的方式重新组合 LWE 样本，然后添加了编码的消息。

### 解密（Decryption）

对于密文 $(\mathbf{a'}, b')$：

1. 计算 $v = b' - \langle \mathbf{a'}, \mathbf{s} \rangle \bmod q$
2. 如果 $v$ 更接近 $\lfloor q/2 \rfloor$（在环 $\mathbb{Z}_q$ 中），则解密结果为 1；否则为 0

更精确地，如果 $|v - \lfloor q/2 \rfloor \bmod q| < q/4$，则输出 1；否则输出 0。

### 正确性分析

解密的正确性取决于错误项的大小。让我们分析解密过程：

$$v = b' - \langle \mathbf{a'}, \mathbf{s} \rangle \bmod q$$

展开 $b'$ 和 $\mathbf{a'}$：

$$v = \sum_{i \in S} b_i + \mu \cdot \lfloor q/2 \rfloor - \langle \sum_{i \in S} \mathbf{a_i}, \mathbf{s} \rangle \bmod q$$

根据 $b_i$ 的定义：

$$v = \sum_{i \in S} (\langle \mathbf{a_i}, \mathbf{s} \rangle + e_i) + \mu \cdot \lfloor q/2 \rfloor - \langle \sum_{i \in S} \mathbf{a_i}, \mathbf{s} \rangle \bmod q$$

化简得：

$$v = \sum_{i \in S} e_i + \mu \cdot \lfloor q/2 \rfloor \bmod q$$

如果累积错误 $\sum_{i \in S} e_i$ 的绝对值小于 $q/4$，则解密将是正确的。这要求错误分布 $\chi$ 的参数和子集 $S$ 的大小适当选择。

## 安全性分析

### 最坏情况到平均情况的归约

Regev 加密方案的一个重要特性是其安全性基于最坏情况到平均情况的归约。具体来说，如果存在一个算法能够以不可忽略的概率攻破随机 LWE 实例，那么这个算法可以用来解决最坏情况下的格问题，如 GapSVP（决策版本的最短向量问题）。

这意味着攻破 Regev 加密方案至少与解决最坏情况下的困难格问题一样难。

### 抗量子攻击能力

LWE 问题被认为对量子计算具有抵抗力。已知的量子算法，如 Shor 算法，能够有效地解决整数分解和离散对数问题，但目前还没有针对 LWE 问题的高效量子攻击算法。

这使得基于 LWE 的密码系统成为后量子密码学的有力候选者。

## 参数选择

Regev 加密方案的安全性和效率很大程度上取决于参数的选择：

- **维度 n**：安全参数，通常选择 256、512 或更高
- **模数 q**：通常选择为多项式大小（相对于 n），如 q ≈ n^2
- **错误分布参数 α**：通常选择 α = 1/(√n·log² n)，使得 αq > 2√n
- **样本数量 m**：通常选择 m = O(n log q)

参数的选择需要平衡安全性和效率。更大的 n 提供更高的安全性，但会增加计算和通信开销。

## 优化与变种

原始的 Regev 加密方案有一些效率问题，例如公钥和密文的大小都较大。为了解决这些问题，研究人员提出了多种优化和变种：

- **环 LWE**：使用多项式环上的 LWE 问题，可以减小密钥和密文的大小
- **基于 LWE 的格签名方案**：如 GPV、BLISS 等
- **全同态加密**：基于 LWE 的全同态加密方案，如 BFV、BGV 等
- **基于身份的加密**：基于 LWE 的基于身份的加密方案

## 应用场景

基于 LWE 的密码系统有广泛的应用前景，特别是在后量子时代：

1. **安全通信**：抵抗量子计算攻击的安全通信协议
2. **数字签名**：后量子数字签名方案
3. **全同态加密**：在加密数据上直接进行计算
4. **功能加密**：支持更复杂的访问控制机制
5. **多方安全计算**：在不泄露输入的情况下进行多方计算

## 参考文献

1. Regev, O. (2005). On lattices, learning with errors, random linear codes, and cryptography. Journal of the ACM (JACM), 56(6), 1-40.
2. Peikert, C. (2009). Public-key cryptosystems from the worst-case shortest vector problem. In Proceedings of the forty-first annual ACM symposium on Theory of computing (pp. 333-342).
3. Micciancio, D., & Regev, O. (2009). Lattice-based cryptography. In Post-quantum cryptography (pp. 147-191). Springer, Berlin, Heidelberg.
4. Lindner, R., & Peikert, C. (2011). Better key sizes (and attacks) for LWE-based encryption. In Topics in Cryptology–CT-RSA 2011 (pp. 319-339). Springer, Berlin, Heidelberg.
5. Alkim, E., Ducas, L., Pöppelmann, T., & Schwabe, P. (2016). Post-quantum key exchange—a new hope. In 25th USENIX Security Symposium (USENIX Security 16) (pp. 327-343).
