/**
 * 对SM4算法的最低限度的实现，实现了对一组128位bit明文的加密与解密
 * 已验证经过1000000次加密后结果与标准结果相符
 * 执行main()函数即可查看加解密结果
 * Author: Szl
 * Date: 2019/1/4
 */
public class SM4 {

    private static long[] CK = {0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    };

    private static long[] FK = {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC};

    private static int[] Sbox = {0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
            0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
            0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
            0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
            0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
            0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
            0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
            0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
            0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
            0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
            0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
            0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
            0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
            0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
            0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
            0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48};

    public static void main(String[] args) {
        String key = "0123456789ABCDEFFEDCBA9876543210"; // 128位bit秘钥
        String plainText = "0123456789ABCDEFFEDCBA9876543210"; // 128位bit明文
        String cipherText = encryption(plainText, key); // 128位bit密文
        System.out.println(cipherText);
        String decryptionText = decryption(cipherText, key); // 128位bit解密后的明文
        System.out.println(decryptionText);
    }

    /**
     * SM4算法加密
     * 如需加密多组明文，可将分解秘钥的步骤移出，只执行一次，提升效率
     * @param plainText 明文字符串
     * @param key 秘钥字符串
     * @return 加密后的密文字符串
     */
    private static String encryption(String plainText, String key) {
        long[] X = splitText(plainText);
        long[] K = expandKey(splitKey(key));
        for (int i = 4; i < X.length; i++) {
            X[i] = xor(X[i-4], L(tao(xor(X[i-3], X[i-2], X[i-1], K[i]))));
        }
        return adverseText(X);
    }

    /**
     * SM4算法解密
     * 解密时逆序使用轮秘钥
     * @param cipherText 密文字符串
     * @param key 秘钥字符串
     * @return 解密后的明文字符串
     */
    private static String decryption(String cipherText, String key) {
        long[] K = expandKey(splitKey(key));
        long[] X = splitText(cipherText);
        for (int i = 4, j= 35; i < X.length; i++, j--) {
            X[i] = xor(X[i-4], L(tao(xor(X[i-3], X[i-2], X[i-1], K[j]))));
        }
        return adverseText(X);
    }

    /**
     * 将128位bit的秘钥拆分为4个32位bit
     * @param key 秘钥字符串
     * @return 长度为4的长整型数组
     */
    private static long[] splitKey(String key) {
        long[] MK = new long[4];
        for (int i = 0; i < MK.length; i++) {
            MK[i] = Long.parseLong(key.substring(i*8, i*8+8), 16);
        }
        return MK;
    }

    /**
     * 将128位bit的明文或密文拆分为4个32位bit
     * @param text 明文十六进制字符串
     * @return 长度为36的轮输出数组，仅前4位有赋值，其值为128位bit明文或密文的拆分，后32位需要经过32轮迭代得出结果
     */
    private static long[] splitText(String text) {
        long[] X = new long[36];
        for (int i = 0; i < 4; i++) {
            X[i] = Long.parseLong(text.substring(i*8, i*8+8), 16);
        }
        return X;
    }

    /**
     * SM4中的秘钥扩展算法
     * 将4个32位bit的秘钥扩展为32个32位bit的轮秘钥，故长整型数组K[]的长度为36
     * @param MK 128位bit秘钥拆分的4个32位bit轮秘钥
     * @return 长度为36的长整型数组，仅前4位有赋值
     */
    private static long[] expandKey(long[] MK) {
        long[] K = new long[36];
        K[0] = xor(MK[0], FK[0]);
        K[1] = xor(MK[1], FK[1]);
        K[2] = xor(MK[2], FK[2]);
        K[3] = xor(MK[3], FK[3]);
        for (int i = 4; i < K.length; i++) {
            K[i] = xor(K[i-4], anotherL(tao(xor(K[i-3], K[i-2], K[i-1], CK[i-4]))));
        }
        return K;
    }

    /**
     * SM4算法中的反序变换
     * 将32次迭代的最后4条结果反序组成最终密文或明文
     * @param X 32轮迭代长整型数组
     * @return 反序变换后的结果，即最终密文或明文
     */
    private static String adverseText(long[] X) {
        StringBuilder builder = new StringBuilder();
        for (int i = X.length - 1; i > X.length - 5; i--) {
            String str = byZeroToString(X[i], 8);
            builder.append(str);
        }
        return builder.toString();
    }

    /**
     * SM4中的一个S盒变换
     * @param a 8位bit的十六进制字符串，长度为2
     * @return S盒变换结果字符串，长度为2
     */
    private static String sBox(String a) {
        int x = charToNum(a.charAt(0));
        int y = charToNum(a.charAt(1));
        return byZeroToString(Sbox[x * 16 + y], 2);
    }

    /**
     * SM4中的4个并行S盒变换
     * @param l 32位bit输入 长整型
     * @return 4个并行S盒变换结果 32位bit 长整型
     */
    private static long tao(long l) {
        String str = byZeroToString(l, 8);
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 8; i+=2) {
            builder.append(sBox(str.substring(i, i+2)));
        }
        return Long.parseLong(builder.toString(), 16);
    }

    /**
     * SM4算法中的L线性变换
     * 即输入比特与其循环左移2位、10位、18位、24位异或的结果
     * @param b 32位bit输入 长整型
     * @return L变换结果 32位bit 长整型
     */
    private static long L(long b) {
        return xor(b, xor(leftShift(b, 2), leftShift(b, 10), leftShift(b, 18), leftShift(b, 24)));
    }

    /**
     * SM4算法中的另一个线性变换，L’变换
     * 即输入比特与其循环左移13位、23位异或的结果
     * @param b 32位bit输入 长整型
     * @return L’变换结果 32位bit 长整型
     */
    private static long anotherL(long b) {
        return xor(b, xor(leftShift(b, 13), leftShift(b, 23)));
    }

    /**
     * 循环左移
     * @param l 32位bit 长整型
     * @param n 左移的位数
     * @return CLR结果 32位bit 长整型
     */
    private static long leftShift(long l, int n) {
        String str = byZeroToString(l, 8);
        String binStr = strToBin(str);
        n = n % 32;
        String afterShiftBin = binStr.substring(n, binStr.length()) + binStr.substring(0, n);
        return Long.parseLong(binToStr(afterShiftBin), 16);
    }

    /**
     * 在十六进制字符串前补0至相应长度
     * 由于Long.toString()方法转换32位bit长整型为字符串时，长度可能不足8，需要补0，其他长度也同样适用
     * @param l 长整型
     * @param length 十六进制字符串应有的长度
     * @return 补0后的结果字符串
     */
    private static String byZeroToString(long l, int length) {
        String str = Long.toString(l, 16);
        int byZero = length - str.length();
        if (byZero != 0) {
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < byZero; i++) {
                builder.append("0");
            }
            builder.append(str);
            return builder.toString();
        } else {
            return str;
        }
    }

    /**
     * 2个32位bit数的异或运算
     * 由于Java中长整型进行32位的异或（^）运算可能会溢出导致负值，故将结果与0x0FFFFFFFFL进行与运算，保证运算结果正确
     * @param l1 长整型
     * @param l2 长整型
     * @return 异或结果 32位bit 长整型
     */
    private static long xor(long l1, long l2) {
        long l = l1 ^ l2;
        return l & 0x0FFFFFFFFL;
    }

    /**
     * 4个32位bit数的异或运算
     * 需注意长整型是否为负值
     * @param l1 长整型
     * @param l2 长整型
     * @param l3 长整型
     * @param l4 长整型
     * @return 异或结果 32位bit 长整型
     */
    private static long xor(long l1, long l2, long l3, long l4) {
        return xor(l1, xor(l2, xor(l3, l4 & 0x0FFFFFFFFL)));
    }

    /**
     * 将十六进制数组转为01数组
     * @param str 十六进制数组
     * @return 二进制数组
     */
    private static String strToBin(String str) {
        StringBuilder binBuilder = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            switch (str.charAt(i)) {
                case '0': binBuilder.append("0000");break;
                case '1': binBuilder.append("0001");break;
                case '2': binBuilder.append("0010");break;
                case '3': binBuilder.append("0011");break;
                case '4': binBuilder.append("0100");break;
                case '5': binBuilder.append("0101");break;
                case '6': binBuilder.append("0110");break;
                case '7': binBuilder.append("0111");break;
                case '8': binBuilder.append("1000");break;
                case '9': binBuilder.append("1001");break;
                case 'A': case 'a': binBuilder.append("1010");break;
                case 'B': case 'b': binBuilder.append("1011");break;
                case 'C': case 'c': binBuilder.append("1100");break;
                case 'D': case 'd': binBuilder.append("1101");break;
                case 'E': case 'e': binBuilder.append("1110");break;
                case 'F': case 'f': binBuilder.append("1111");break;
                default: break;
            }
        }
        return binBuilder.toString();
    }

    /**
     * 将01数组转为十六进制数组
     * @param bin 二进制数组
     * @return 十六进制数组
     */
    private static String binToStr(String bin) {
        StringBuilder strBuilder = new StringBuilder();
        for (int i = 0; i < bin.length(); i += 4) {
            switch (bin.substring(i, i+4)) {
                case "0000": strBuilder.append("0");break;
                case "0001": strBuilder.append("1");break;
                case "0010": strBuilder.append("2");break;
                case "0011": strBuilder.append("3");break;
                case "0100": strBuilder.append("4");break;
                case "0101": strBuilder.append("5");break;
                case "0110": strBuilder.append("6");break;
                case "0111": strBuilder.append("7");break;
                case "1000": strBuilder.append("8");break;
                case "1001": strBuilder.append("9");break;
                case "1010": strBuilder.append("A");break;
                case "1011": strBuilder.append("B");break;
                case "1100": strBuilder.append("C");break;
                case "1101": strBuilder.append("D");break;
                case "1110": strBuilder.append("E");break;
                case "1111": strBuilder.append("F");break;
                default:break;
            }
        }
        return strBuilder.toString();
    }

    /**
     * 将字符转为整型
     * @param c 字符
     * @return 整型结果
     */
    private static int charToNum(char c) {
        switch (c) {
            case '0': return 0;
            case '1': return 1;
            case '2': return 2;
            case '3': return 3;
            case '4': return 4;
            case '5': return 5;
            case '6': return 6;
            case '7': return 7;
            case '8': return 8;
            case '9': return 9;
            case 'A': case 'a': return 10;
            case 'B': case 'b': return 11;
            case 'C': case 'c': return 12;
            case 'D': case 'd': return 13;
            case 'E': case 'e': return 14;
            case 'F': case 'f': return 15;
            default: return -1;
        }
    }
}
