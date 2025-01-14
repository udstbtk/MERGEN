#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <linux/libptr.h>

#define SHA256_DIGEST_SIZE 32
#define RADIX_START 58
#define RADIX_END 63
#define VERSION_START 54
#define VERSION_END 57
#define VERSION_SIZE 4
#define CHECKSUM_START 48
#define CHECKSUM_END 53
#define CHECKSUM_SIZE 6

uint8_t libptr_Sbox[16] = {0x0C, 0x05, 0x06, 0x0B, 0x09, 0x00, 0x0A, 0x0D, 
                0x03, 0x0E, 0x0F, 0x08, 0x04, 0x07, 0x01, 0x02};

uint8_t inv_libptr_Sbox[16] = {0x05, 0x0E, 0x0F, 0x08, 0x0C, 0x01, 0x02, 0x0D, 0x0B, 0x04, 0x06, 0x03, 0x00, 0x07, 0x09, 0x0A};

uint8_t Perm[4][24] = {{0,8,12,16,1,4,17,20,5,9,13,21,2,10,14,18,3,6,19,22,7,11,15,23},
                {1,9,13,17,2,5,18,21,6,10,14,22,3,11,15,19,0,7,16,23,4,8,12,20},
                {2,10,14,18,3,6,19,22,7,11,15,23,0,8,12,16,1,4,17,20,5,9,13,21},
                {3,11,15,19,0,7,16,23,4,8,12,20,1,9,13,17,2,5,18,21,6,10,14,22}
};

uint8_t inv_Perm[4][24] = {
    {0,4,12,16,5,8,17,20,1,9,13,21,2,10,14,22,3,6,15,18,7,11,19,23},
    {16,0,4,12,20,5,8,17,21,1,9,13,22,2,10,14,18,3,6,15,23,7,11,19},
    {12,16,0,4,17,20,5,8,13,21,1,9,14,22,2,10,15,18,3,6,19,23,7,11},
    {4,12,16,0,8,17,20,5,9,13,21,1,10,14,22,2,6,15,18,3,11,19,23,7}
};

static void key_schedule(uint8_t * masterkey, uint8_t * round_keys){
    int i;
    for(i=0; i<256; i++)
        round_keys[i] = masterkey[i];

    for(i=256; i<384; i++)
        round_keys[i] = masterkey[i-256] ^ masterkey[i-128];

}

static void rotation_with_key(uint8_t *input, uint8_t *key){
    uint8_t i;
    uint8_t rot1 = (key[0]<<1) ^ (key[1]);
    uint8_t rot2 = (key[2]<<2) ^ (key[3]<<1) ^ (key[4]);

    for(i=0;i<24;i++)
        input[i]^= input[(i+1+rot1)%24] ^ input[(i+6+rot2)%24];
}

static void inv_rotation_with_key(uint8_t *input, uint8_t *key){
    int i;
    uint8_t rot1 = (key[0]<<1) ^ (key[1]);
    uint8_t rot2 = (key[2]<<2) ^ (key[3]<<1) ^ (key[4]);

    for(i=23;i>=0;i--)
        input[i]^= input[(i+1+rot1)%24] ^ input[(i+6+rot2)%24];
}

static void permutation_with_key(uint8_t *input, uint8_t *key, uint8_t *output){
    uint8_t i;
    uint8_t perm_number = (key[5]<<1) ^ (key[6]);
 
    for(i=0;i<24;i++)
        output[i] = input[Perm[perm_number][i]];
    
}
static void inv_permutation_with_key(uint8_t *input, uint8_t *key, uint8_t *output){
    uint8_t i;
    uint8_t perm_number = (key[5]<<1) ^ (key[6]);
 
    for(i=0;i<24;i++)
        output[i] = input[inv_Perm[perm_number][i]];
}

static void tweak_non_linear(uint8_t *input, uint8_t *output){
    uint8_t i;
    for(i=0;i<53;i++)
        output[i] = input[i] ^ (input[(i+1)%53] ^ 1)*(input[(i+2)%53]); 
}

static void perm_tweak(uint8_t *input, uint8_t *key, uint8_t *output){
    uint8_t i;
    uint8_t rotnumber = (key[0]<<3) ^ (key[1]<<2) ^ (key[2]<<1) ^ (key[3]);
    for(i=0;i<53;i++)
        output[i] = input[(i + i*rotnumber)%53];
}
static void rotation_with_key_tweak(uint8_t *input, uint8_t *key, uint8_t *output){
    uint8_t i;
    uint8_t rot1 = key[0];
    uint8_t rot2 = (key[0]<<2) ^ (key[1]<<1) ^ (key[2]);
    
    for(i=0;i<53;i++)
        output[i] = input[i] ^ input[(i+1+rot1)%53] ^ input[(i+3+rot2)%53];
}

static void tweak_getkey(uint8_t *tweak, uint8_t *roundkeys, uint8_t *output_keys, uint8_t round_number){
    uint8_t temp[53], temp2[53], temp3[53];
    uint8_t i, j, r;
    for(i=0;i<40;i++)
        temp[i] = tweak[i];
    temp[40] = 1;
    for(i=0;i<12;i++)
        temp[i+41] = 0;
    
    for(r=0;r<round_number;r++){
        for(i=0;i<53;i++)
            temp[i] ^= roundkeys[r*60 + 24 + 7 + i];  
    
        tweak_non_linear(temp, temp2);
    
        rotation_with_key_tweak(temp2, roundkeys + 60*r + 24 + 7, temp3);
    
        perm_tweak(temp3, roundkeys + 60*r + 24 + 7 + 3, temp);

        for (i=0;i<7;i++)
            output_keys[i+60*r]=roundkeys[i+60*r+24];

        for(i=0;i<  53   ;i++)
            output_keys[r*60 + i + 7] = temp[i];
    }
}

static void round_encrypt(uint8_t *input, uint8_t *key, uint8_t *output){
    uint8_t i,  temp[6], tempbits[24], tempbits2[24], tempbits3[24];
    uint8_t ayarbit[14]={0};

    for (i=0;i<7;i++)
        ayarbit[i]=key[i];

    for (i=0;i<5;i++)
        ayarbit[i+7]=key[48+7+i];

    for(i=0;i<12;i+=2)
        ayarbit[12]^= ayarbit[i];

    for(i=1;i<12;i+=2)
        ayarbit[13]^= ayarbit[i];

    temp[0] = libptr_Sbox[(input[0]<<3)^(input[1]<<2)^(input[2]<<1)^(input[3])];
    temp[1] = libptr_Sbox[(input[4]<<3)^(input[5]<<2)^(input[6]<<1)^(input[7])];
    temp[2] = libptr_Sbox[(input[8]<<3)^(input[9]<<2)^(input[10]<<1)^(input[11])];
    temp[3] = libptr_Sbox[(input[12]<<3)^(input[13]<<2)^(input[14]<<1)^(input[15])];
    temp[4] = libptr_Sbox[(input[16]<<3)^(input[17]<<2)^(input[18]<<1)^(input[19])];
    temp[5] = libptr_Sbox[(input[20]<<3)^(input[21]<<2)^(input[22]<<1)^(input[23])];

    for(i=0;i<6;i++){
        tempbits[4*i] = (temp[i]>>3)&1;
        tempbits[4*i+1] = (temp[i]>>2)&1;
        tempbits[4*i+2] = (temp[i]>>1)&1;
        tempbits[4*i+3] = (temp[i])&1;
    }

    permutation_with_key(tempbits, ayarbit, tempbits2);
    
    rotation_with_key(tempbits2, ayarbit);

    // anahtarı ekle
    for(i=0;i<24;i++)
        tempbits2[i]^=key[i+7];

    temp[0] = libptr_Sbox[(tempbits2[0]<<3)^(tempbits2[1]<<2)^(tempbits2[2]<<1)^(tempbits2[3])];
    temp[1] = libptr_Sbox[(tempbits2[4]<<3)^(tempbits2[5]<<2)^(tempbits2[6]<<1)^(tempbits2[7])];
    temp[2] = libptr_Sbox[(tempbits2[8]<<3)^(tempbits2[9]<<2)^(tempbits2[10]<<1)^(tempbits2[11])];
    temp[3] = libptr_Sbox[(tempbits2[12]<<3)^(tempbits2[13]<<2)^(tempbits2[14]<<1)^(tempbits2[15])];
    temp[4] = libptr_Sbox[(tempbits2[16]<<3)^(tempbits2[17]<<2)^(tempbits2[18]<<1)^(tempbits2[19])];
    temp[5] = libptr_Sbox[(tempbits2[20]<<3)^(tempbits2[21]<<2)^(tempbits2[22]<<1)^(tempbits2[23])];

    for(i=0;i<6;i++){
        tempbits[4*i] = (temp[i]>>3)&1;
        tempbits[4*i+1] = (temp[i]>>2)&1;
        tempbits[4*i+2] = (temp[i]>>1)&1;
        tempbits[4*i+3] = (temp[i])&1;
    }
    permutation_with_key(tempbits, ayarbit+7, tempbits2);
    
    rotation_with_key(tempbits2, ayarbit+7);

    // anahtarın kalanını ekle
    for(i=0;i<24;i++)
        output[i] = tempbits2[i]^key[i+24+7];
}

static void round_decrypt(uint8_t *input, uint8_t *key, uint8_t *output){
    uint8_t i,  temp[6], tempbits[24], tempbits2[24], tempbits3[24];
    uint8_t ayarbit[14]={0};

    for (i=0;i<7;i++)
        ayarbit[i]=key[i];

    for (i=0;i<5;i++)
        ayarbit[i+7]=key[48+7+i];

    for(i=0;i<12;i+=2)
        ayarbit[12]^= ayarbit[i];

    for(i=1;i<12;i+=2)
        ayarbit[13]^= ayarbit[i];

     // anahtarın sonunu ekle
    for(i=0;i<24;i++)
        tempbits[i] = input[i]^key[i+24+7];

    inv_rotation_with_key(tempbits, ayarbit+7);

    inv_permutation_with_key(tempbits, ayarbit+7, tempbits2);

    temp[0] = inv_libptr_Sbox[(tempbits2[0]<<3)^(tempbits2[1]<<2)^(tempbits2[2]<<1)^(tempbits2[3])];
    temp[1] = inv_libptr_Sbox[(tempbits2[4]<<3)^(tempbits2[5]<<2)^(tempbits2[6]<<1)^(tempbits2[7])];
    temp[2] = inv_libptr_Sbox[(tempbits2[8]<<3)^(tempbits2[9]<<2)^(tempbits2[10]<<1)^(tempbits2[11])];
    temp[3] = inv_libptr_Sbox[(tempbits2[12]<<3)^(tempbits2[13]<<2)^(tempbits2[14]<<1)^(tempbits2[15])];
    temp[4] = inv_libptr_Sbox[(tempbits2[16]<<3)^(tempbits2[17]<<2)^(tempbits2[18]<<1)^(tempbits2[19])];
    temp[5] = inv_libptr_Sbox[(tempbits2[20]<<3)^(tempbits2[21]<<2)^(tempbits2[22]<<1)^(tempbits2[23])];

    for(i=0;i<6;i++){
        tempbits3[4*i] = (temp[i]>>3)&1;
        tempbits3[4*i+1] = (temp[i]>>2)&1;
        tempbits3[4*i+2] = (temp[i]>>1)&1;
        tempbits3[4*i+3] = (temp[i])&1;
    }

    // anahtarın başını ekle
    for(i=0;i<24;i++)
        tempbits3[i]^=key[i+7];

    inv_rotation_with_key(tempbits3, ayarbit);

    inv_permutation_with_key(tempbits3, ayarbit, tempbits2);

    temp[0] = inv_libptr_Sbox[(tempbits2[0]<<3)^(tempbits2[1]<<2)^(tempbits2[2]<<1)^(tempbits2[3])];
    temp[1] = inv_libptr_Sbox[(tempbits2[4]<<3)^(tempbits2[5]<<2)^(tempbits2[6]<<1)^(tempbits2[7])];
    temp[2] = inv_libptr_Sbox[(tempbits2[8]<<3)^(tempbits2[9]<<2)^(tempbits2[10]<<1)^(tempbits2[11])];
    temp[3] = inv_libptr_Sbox[(tempbits2[12]<<3)^(tempbits2[13]<<2)^(tempbits2[14]<<1)^(tempbits2[15])];
    temp[4] = inv_libptr_Sbox[(tempbits2[16]<<3)^(tempbits2[17]<<2)^(tempbits2[18]<<1)^(tempbits2[19])];
    temp[5] = inv_libptr_Sbox[(tempbits2[20]<<3)^(tempbits2[21]<<2)^(tempbits2[22]<<1)^(tempbits2[23])];

    for(i=0;i<6;i++){
        tempbits[4*i] = (temp[i]>>3)&1;
        tempbits[4*i+1] = (temp[i]>>2)&1;
        tempbits[4*i+2] = (temp[i]>>1)&1;
        tempbits[4*i+3] = (temp[i])&1;
    }

    for(i=0;i<24;i++)
        output[i]=tempbits[i];
}

static void ca_encrypt(uint8_t *pointer, uint8_t *masterkey){
    int round_number = 6;
    uint8_t *roundkeys = kmalloc(384* sizeof(uint8_t), GFP_KERNEL);
    key_schedule(masterkey, roundkeys);

    uint8_t i, j, r;
    uint8_t temp[24], temp2[24];
    uint8_t final_keys[360];
    uint8_t tweak[40]={0};
    uint8_t upper[24];
    uint8_t radix=0;

    // tweak ve radixi ayarla
    for(i = 0; i<6; i++){
        tweak[i]=pointer[i];
        radix+= pointer[i]<<(5-i);
    }

    for(i =30;i<64;i++)
        tweak[i-24]=pointer[i];
    
    // şifrelenecek adres bitlerini al
    for (i=6;i<30;i++)
        upper[i-6]=pointer[i];
    
    // radixe göre tweakin son kısmı padding yap. offset kısmının bitlerini 0 yap yani.
    for (i=63;i>(63-radix);i--)
        tweak[i-24]=0;

    //key whitining

    for(i=0;i<24;i++)
        temp[i] = upper[i] ^ roundkeys[i];
    

    tweak_getkey(tweak,roundkeys,final_keys,6);

    for(r=0;r<round_number;r++){
        round_encrypt(temp, final_keys+60*r, temp2);        
        
        for(int o=0;o<24;o++)
            temp[o]=temp2[o];
    }
    for(i = 0; i<24;i++)
        pointer[i+6]=temp[i];

    kfree(roundkeys);
}

static void ca_decrypt(uint8_t *pointer, uint8_t *masterkey){
    int round_number = 6;
    uint8_t *roundkeys = kmalloc(384* sizeof(uint8_t), GFP_KERNEL);
    key_schedule(masterkey, roundkeys);
    int r;
    uint8_t i, j;
    uint8_t temp[24], temp2[24];
    uint8_t final_keys[360];
    uint8_t tweak[40]={0};
    uint8_t upper[24];
    uint8_t radix=0;

    // tweak ve radixi ayarla
    for(i = 0; i<6; i++){
        tweak[i]=pointer[i];
        radix+= pointer[i]<<(5-i);
    }

    for(i =30;i<64;i++)
        tweak[i-24]=pointer[i];
    
    // şifrelenecek adres bitlerini al
    for (i=6;i<30;i++)
        upper[i-6]=pointer[i];
    
    // radixe göre tweakin son kısmı padding yap. offset kısmının bitlerini 0 yap yani.
    for (i=63;i>(63-radix);i--)
        tweak[i-24]=0;
    
    tweak_getkey(tweak,roundkeys,final_keys,6);

    for(i=0;i<24;i++)
        temp[i] = upper[i];

    for(r=5;r>=0;r--){
        round_decrypt(temp, final_keys+60*r, temp2);   

        for(int o=0;o<24;o++)
            temp[o]=temp2[o];
    }

    for(i=0;i<24;i++)
        temp[i] ^= roundkeys[i];
    
    for(i = 0; i<24;i++)
        pointer[i+6]=temp[i];

    kfree(roundkeys);
}

static unsigned long long get_random_bits(int size){
    unsigned long long bits = 0;

    for (int i = 0; i < size; i++)
    {
        unsigned char random_byte;
        get_random_bytes(&random_byte, 1);
        bits = (bits << 1) | (random_byte & 1);
    }

    return bits;
}

static int get_hash_bits(unsigned long long input, int count){
    struct crypto_shash *tfm;
    struct sdesc {
        struct shash_desc shash;
        char ctx[];
    } *sdesc;
    int size, ret;
    unsigned char bytes[sizeof(input)];
    unsigned char hash[SHA256_DIGEST_SIZE];

    memcpy(bytes, &input, sizeof(input));

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Failed to allocate sha256 tfm\n");
        return PTR_ERR(tfm);
    }

    size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc) {
        pr_err("Failed to allocate sdesc\n");
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    sdesc->shash.tfm = tfm;

    ret = crypto_shash_digest(&sdesc->shash, bytes, sizeof(bytes), hash);
    if (ret) {
        pr_err("SHA256 digest failed\n");
        kfree(sdesc);
        crypto_free_shash(tfm);
        return ret;
    }

    kfree(sdesc);
    crypto_free_shash(tfm);

    return (hash[0] >> (8 - count));
}

static void update_bits(unsigned long long *input, int start, int end, unsigned long long update){
    unsigned long long mask = ((1ULL << (end - start + 1)) - 1) << start;

    *input &= ~mask;
    *input |= (update << start) & mask;
}

static int check_bits(unsigned long long input, int start, int end, unsigned long long value){
    unsigned long long mask = ((1ULL << (end - start + 1)) - 1) << start;

    unsigned long long bits = (input & mask) >> start;

    return bits == value;
}

static unsigned long long get_bits(unsigned long long input, int start, int end){
    unsigned long long mask = ((1ULL << (end - start + 1)) - 1) << start;

    unsigned long long bits = (input & mask) >> start;

    return bits;
}

static void bits_to_array(unsigned long long input, uint8_t *bitArray, int size){
    for (int i = 0; i < size; i++)
    {
        bitArray[size - i - 1] = (input >> i) & 1;
    }
}

static unsigned long long array_to_bits(uint8_t *bitArray, int size){
    unsigned long long output = 0;

    for (int i = 0; i < size; i++)
    {
        output = (output << 1) | bitArray[i];
    }
    return output;   
}

unsigned long long ptr_encrypt(unsigned long long ptr, size_t size){
    unsigned long long output = ptr;
    int t = 1, radix = 0;

    while(t < size){ // Radix Hesaplama
        radix++;
        t <<= 1;
    }

    update_bits(&output, RADIX_START, RADIX_END, radix); //radix ekle

    int version = get_random_bits(VERSION_SIZE); // Versiyonun alınması
    update_bits(&output, VERSION_START, VERSION_END, version); // Versiyonun eklenmesi

    unsigned long long hashed = output;
    update_bits(&hashed, 0, radix - 1, 0ULL); // Checksum kısmında offset olmamalı

    int checksum = get_hash_bits(hashed, CHECKSUM_SIZE); // Checksum bitlerinin alınması
    update_bits(&output, CHECKSUM_START, CHECKSUM_END, checksum); // Checksum bitlerinin eklenmesi

    uint8_t pointerBits[64], masterkeyBits[256];

    bits_to_array(output, pointerBits, 64);
    for (int i = 0; i < 4; i++)
    {
        bits_to_array(current->master_key[i], masterkeyBits + 64 * i, 64);
    }

    ca_encrypt(pointerBits, masterkeyBits); // Kriptografik Adresin şifrelenmesi
    output = array_to_bits(pointerBits, 64); // Çıktı formatına çevrilmesi

    return output;
}
EXPORT_SYMBOL(ptr_encrypt);

unsigned long long ptr_decrypt(unsigned long long ptr, size_t size){
    unsigned long long output = ptr;
    int radix = get_bits(output, RADIX_START, RADIX_END);
    uint8_t pointerBits[64], masterkeyBits[256];

    bits_to_array(output, pointerBits, 64); // Girdileri hazırla
    for (int i = 0; i < 4; i++)
    {
        bits_to_array(current->master_key[i], masterkeyBits + 64 * i, 64);
    }

    ca_decrypt(pointerBits, masterkeyBits); // Kriptografik adresi deşifre et
    output = array_to_bits(pointerBits, 64);

    int given_checksum = get_bits(output, CHECKSUM_START, CHECKSUM_END);
    unsigned long long hashed = output;
    update_bits(&hashed, 0, radix - 1, 0ULL); // offset kısmı hashde olmamalı
    update_bits(&hashed, CHECKSUM_START, CHECKSUM_END, 0ULL); // Chesksum kısmı hashde olmamalı

    int calculated_checksum = get_hash_bits(hashed, CHECKSUM_SIZE);

    if(calculated_checksum != given_checksum){ // Checksum kontrolü
        return 0ULL; //boş pointer dön SIGSEGV
    }

    int bit = get_bits(output, 47, 47); // 16 kullanılmayan bitin 47. bite eşit olması gerekir
    bit = bit ? (1 << 16) - 1 : 0ULL; // genişlet
    update_bits(&output, 48, 63, bit);

    return output;
}
EXPORT_SYMBOL(ptr_decrypt);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("obaw");
MODULE_DESCRIPTION("Pointer Encryption Library");
