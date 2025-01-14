// ***********************************************
// *                                             *
// *                                             *      ╱|、
// *  Çekirdek Kodlarının Geri Kalanı Buradaydı  *     (˚ˎ。7
// *                                             *      |、˜〵
// *                                             *      じしˍ,)ノ
// ***********************************************

#include <linux/libptr.h> // Kütüphanelerimizin dahil edilmesi
#include <linux/present.h>

// Çekirdeğin sağladığı sistem çağrısı tanımlama şablonu
SYSCALL_DEFINE2(encptr, void __user*, ptr, size_t, size) {
    // İşaretçi Şifreleme Kısmı
	unsigned long long kernel_ptr; // Kullanılacak değişkenlerin tanımlanması
    unsigned long long encrypted_ptr;
    void __user *data_ptr;

    // İşaretçinin Kullanıcı belleğinden çekirdek belleğine kopyalanması
    if (copy_from_user(&kernel_ptr, ptr, sizeof(ptr))) {
        return -EFAULT; // Hata durumunda hata kodu dönülmesi
    }

    encrypted_ptr = ptr_encrypt(kernel_ptr); // İşaretçinin şifrelenmesi

    // Şifrelenmiş İşaretçinin kullanıcı belleğine yazılması
    if (copy_to_user(ptr, &encrypted_ptr, sizeof(ptr))) {
        return -EFAULT;
    }

    // Veri Şifreleme Kısmı
    // Verinin bayt bayt XOR anahtarıyla XOR işleminden geçirilmesi
    data_ptr = (void __user *)kernel_ptr;
    for (size_t i = 0; i < size; i++) {
        char encptr_text[17], masterkey_text[21], xorkey_text[3];
        char* temp;
        unsigned char xor_key;

        // Girdilerin Present girdi formatına çevrilmesi
        snprintf(encptr_text, 17, "%16llx", encrypted_ptr + i);
        snprintf(masterkey_text, 17, "%16llx", current->master_key[0]);
        snprintf(masterkey_text + 16, 5, "%04llx", (current->master_key[1] >> 16) & 0xFFFF);

        temp = present_encrypt(encptr_text, masterkey_text);
        strscpy(xorkey_text, temp, 3);

        // XOR anahtarının eldesi
        kstrtou8(xorkey_text, 16, &xor_key);

        unsigned char byte;
        if (copy_from_user(&byte, data_ptr + i, sizeof(byte))) {
            return -EFAULT;
        }

        byte ^= xor_key;

        if (copy_to_user(data_ptr + i, &byte, sizeof(byte))) {
            return -EFAULT;
        }
    }

    return 0;
}

SYSCALL_DEFINE2(decptr, void __user*, ptr, size_t, size) {
	unsigned long long kernel_ptr;
    unsigned long long decrypted_ptr;
    void __user *data_ptr;
     
    if (copy_from_user(&kernel_ptr, ptr, sizeof(ptr))) {
        return -EFAULT;
    }

    decrypted_ptr = ptr_decrypt(kernel_ptr);

    if (copy_to_user(ptr, &decrypted_ptr, sizeof(ptr))) {
        return -EFAULT;
    }

    data_ptr = (void __user *)decrypted_ptr;
    for (size_t i = 0; i < size; i++) {
        char encptr_text[17], masterkey_text[21], xorkey_text[3];
        char* temp;
        unsigned char xor_key;

        snprintf(encptr_text, 17, "%16llx", kernel_ptr + i);
        snprintf(masterkey_text, 17, "%16llx", current->master_key[0]);
        snprintf(masterkey_text + 16, 5, "%04llx", (current->master_key[1] >> 16) & 0xFFFF);

        temp = present_encrypt(encptr_text, masterkey_text);
        strscpy(xorkey_text, temp, 3);

        kstrtou8(xorkey_text, 16, &xor_key);

        unsigned char byte;
        if (copy_from_user(&byte, data_ptr + i, sizeof(byte))) {
            return -EFAULT;
        }
        
        byte ^= xor_key;

        if (copy_to_user(data_ptr + i, &byte, sizeof(byte))) {
            return -EFAULT;
        }
    }

    return 0;
}