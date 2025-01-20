import java.util.Arrays;

// Klasa abstrakcyjna definiująca strukturę szyfru
abstract class Cipher {

    private int keyLength;

    // Konstruktor ustawia długość klucza
    Cipher(int keyLength) {
        this.keyLength = keyLength;
    }
    // Abstrakcyjna metoda do inicjalizacji klucza (do zaimplementowania przez klasy dziedziczące)
    protected abstract void initializeKey(byte[] key);

    // Abstrakcyjna metoda przetwarzająca blok danych (do zaimplementowania przez klasy dziedziczące)
    public abstract void processBlock(byte[] data, int offset);

    // Metoda umożliwiająca inicjalizację klucza na podstawie hasła
    protected void initializeKey(String password) {
        initializeKey(KeyUtils.createKey(password, keyLength));
    }
    // Domyślna implementacja przetwarzania bloku zaczyna od offsetu 0
    public void processBlock(byte[] data) {
        processBlock(data, 0);
    }
}

// Klasa pomocnicza zawierająca metody dla operacji na kluczach
class KeyUtils {

    //generuje klucz kryptograficzny na podstawie hasła, wykonując operację XOR na każdym bajcie hasła
    public static byte[] createKey(String password, int length) {
        //tablica wypelniana zerami
        byte[] key = new byte[length];
        Arrays.fill(key, (byte) 0);
        /*
        Pętla przechodzi przez wszystkie znaki hasła.
        Indeks i odpowiada bieżącemu znakowi hasła, a j odnosi się do pozycji w tablicy key.
        Indeks j jest "zawijany" do zakresu długości tablicy klucza (key.length) za pomocą operatora modulo (%).
        Dzięki temu nawet jeśli hasło jest dłuższe niż klucz, znaki hasła są wielokrotnie stosowane na różnych pozycjach w kluczu.
         */
        // XOR-uje każdy bajt hasła z odpowiednimi elementami tablicy klucza
        for (int i = 0, j = 0; i < password.length(); i++, j = (j + 1) % key.length) {
            key[j] ^= (byte) password.charAt(i);
        }
        return key;
    }

    // Łączy dwa bajty w jedną 16-bitową wartość (int)
    static int combineBytes(int byte1, int byte2) {
        byte1 = (byte1 & 0xFF) << 8; // Przesuwa pierwszy bajt o 8 bitów w lewo
        byte2 = byte2 & 0xFF;  // Wyodrębnia mniej znaczące 8 bitów drugiego bajtu
        return byte1 | byte2;  // Łączy dwa bajty w jeden 16-bitowy int
    }
}

class IdeaCipher extends Cipher {

    private static final int KEY_LENGTH = 16; // Długość klucza (16 bajtów)
    private static final int NUM_ROUNDS = 8; // Liczba rund IDEA

    private boolean isEncryptionMode; // Tryb szyfrowania (true) lub deszyfrowania (false)
    private int[] subKeys;  // Tablica podkluczy używanych w IDEA

    // Konstruktor, inicjalizuje szyfr z hasłem i trybem (szyfrowanie/deszyfrowanie)
    public IdeaCipher(String password, boolean isEncryptionMode) {
        super(KEY_LENGTH); // Ustawia długość klucza
        this.isEncryptionMode = isEncryptionMode; // Ustawia tryb pracy
        initializeKey(password); // Inicjalizuje klucz
    }

    // Inicjalizacja klucza i generacja podkluczy
    @Override
    protected void initializeKey(byte[] key) {
        int[] tempSubKeys = generateSubKeys(key); // Generuje podklucze
        subKeys = isEncryptionMode ? tempSubKeys : invertSubKeys(tempSubKeys);//w zależnosci od trybu podklucze normalne lub odwrócone
    }

    // Przetwarza jeden blok danych
    @Override
    public void processBlock(byte[] data, int offset) {
        // Wczytuje 4 16-bitowe wartości z danych wejściowych
        int x1 = KeyUtils.combineBytes(data[offset], data[offset + 1]);
        int x2 = KeyUtils.combineBytes(data[offset + 2], data[offset + 3]);
        int x3 = KeyUtils.combineBytes(data[offset + 4], data[offset + 5]);
        int x4 = KeyUtils.combineBytes(data[offset + 6], data[offset + 7]);


        // Przetwarzanie w rundach
        int roundIndex = 0; // Indeks podklucza
        for (int round = 0; round < NUM_ROUNDS; round++) {
            // Operacje matematyczne IDEA: mnożenie modularne, dodawanie modularne i XOR

            int y1 = multiply(x1, subKeys[roundIndex++]);
            int y2 = add(x2, subKeys[roundIndex++]);
            int y3 = add(x3, subKeys[roundIndex++]);
            int y4 = multiply(x4, subKeys[roundIndex++]);
            int y5 = y1 ^ y3;
            int y6 = y2 ^ y4;
            int y7 = multiply(y5, subKeys[roundIndex++]);
            int y8 = add(y6, y7);
            int y9 = multiply(y8, subKeys[roundIndex++]);
            int y10 = add(y7, y9);

            // Aktualizacja rejestrów dla następnej rundy
            x1 = y1 ^ y9;
            x2 = y3 ^ y9;
            x3 = y2 ^ y10;
            x4 = y4 ^ y10;
        }

        // Finalne operacje matematyczne
        int result0 = multiply(x1, subKeys[roundIndex++]);
        int result1 = add(x3, subKeys[roundIndex++]);
        int result2 = add(x2, subKeys[roundIndex++]);
        int result3 = multiply(x4, subKeys[roundIndex]);

        //liczby result1 ... są 16 bitowe i żeby je zapisać w tablicy to zapisujemy po 8 bitów najpierw 8 bitów najbardziej znaczących a potem 8 bitów mniej znaczących
        data[offset] = (byte) (result0 >> 8); //zapisuje wyższy bajt z result1 w tablicy data.
        data[offset + 1] = (byte) result0;//zapisuje niższy bajt z result1 w  tablicy data.
        data[offset + 2] = (byte) (result1 >> 8);
        data[offset + 3] = (byte) result1;
        data[offset + 4] = (byte) (result2 >> 8);
        data[offset + 5] = (byte) result2;
        data[offset + 6] = (byte) (result3 >> 8);
        data[offset + 7] = (byte) result3;
    }

    // Generuje podklucze IDEA
    private static int[] generateSubKeys(byte[] userKey) {
        if (userKey.length != 16) throw new IllegalArgumentException("Key length must be 16 bytes.");
        int[] subKeys = new int[NUM_ROUNDS * 6 + 4];

        // Tworzenie początkowych podkluczy na podstawie klucza użytkownika
        for (int i = 0; i < 8; i++) {
            subKeys[i] = KeyUtils.combineBytes(userKey[2 * i], userKey[2 * i + 1]);
        }

        // Generacja kolejnych podkluczy poprzez przesunięcia bitowe
        for (int i = 8; i < subKeys.length; i++) {
            int part1 = subKeys[(i + 1) % 8 != 0 ? i - 7 : i - 15] << 9;
            int part2 = subKeys[(i + 2) % 8 < 2 ? i - 14 : i - 6] >>> 7;
            subKeys[i] = (part1 | part2) & 0xFFFF;
        }

        return subKeys;
    }
    // Odwraca podklucze dla deszyfrowania
    private static int[] invertSubKeys(int[] subKeys) {
        int[] invertedSubKeys = new int[subKeys.length];
        int index = 0, i = NUM_ROUNDS * 6;

        // Operacje matematyczne dla odwrócenia kluczy
        invertedSubKeys[i] = multiplyInverse(subKeys[index++]);
        invertedSubKeys[i + 1] = addInverse(subKeys[index++]);
        invertedSubKeys[i + 2] = addInverse(subKeys[index++]);
        invertedSubKeys[i + 3] = multiplyInverse(subKeys[index++]);

        for (int round = NUM_ROUNDS - 1; round > 0; round--) {
            i = round * 6;
            invertedSubKeys[i + 4] = subKeys[index++];
            invertedSubKeys[i + 5] = subKeys[index++];
            invertedSubKeys[i] = multiplyInverse(subKeys[index++]);
            invertedSubKeys[i + 2] = addInverse(subKeys[index++]);
            invertedSubKeys[i + 1] = addInverse(subKeys[index++]);
            invertedSubKeys[i + 3] = multiplyInverse(subKeys[index++]);
        }

        invertedSubKeys[4] = subKeys[index++];
        invertedSubKeys[5] = subKeys[index++];
        invertedSubKeys[0] = multiplyInverse(subKeys[index++]);
        invertedSubKeys[1] = addInverse(subKeys[index++]);
        invertedSubKeys[2] = addInverse(subKeys[index++]);
        invertedSubKeys[3] = multiplyInverse(subKeys[index]);

        return invertedSubKeys;
    }

    // Dodawanie modularne
    private static int add(int x, int y) {
        return (x + y) & 0xFFFF;
    }

    //Dodawanie odwrotne
    private static int addInverse(int x) {
        return (0x10000 - x) & 0xFFFF;
    }

    //Mnożenie modularne
    private static int multiply(int x, int y) {
        long result = (long) x * y;
        return result != 0 ? (int) (result % 0x10001) & 0xFFFF : (1 - x - y) & 0xFFFF;
    }

    //Mnożenie odwrotne
    private static int multiplyInverse(int x) {
        if (x <= 1) return x;
        int t0 = 1, t1 = 0, y = 0x10001;

        while (true) {
            t1 += y / x * t0;
            y %= x;
            if (y == 1) return (1 - t1) & 0xFFFF;
            t0 += x / y * t1;
            x %= y;
            if (x == 1) return t0;
        }
    }
}

public class Main {

    private static byte[] encrypt(byte[] data, String key) {
        // IDEA działa na blokach danych o długości 8 bajtów.
        // Jeśli dane wejściowe nie są wielokrotnością 8 bajtów, musimy dodać padding.
        int blockLength = 8;

        // Obliczamy minimalną długość, która jest wielokrotnością 8 bajtów.
        // Jeśli dane mają długość np. 10, to paddedLength = 16 (następna wielokrotność 8).
        int paddedLength = (data.length + blockLength - 1) / blockLength * blockLength;//obliczamy minimalna wielkosc ktora jest wielokrotnoscia 8

        // Tworzymy nową tablicę, wypełnioną zerami, której długość jest równa paddedLength.
        byte[] paddedData = Arrays.copyOf(data, paddedLength);

        // Tablica, która przechowa zaszyfrowane dane.
        byte[] encryptedData = new byte[paddedLength];

        // Inicjalizujemy szyfr IDEA w trybie szyfrowania (drugi parametr `true`).
        IdeaCipher cipher = new IdeaCipher(key, true);

        // Przetwarzamy dane blokami po 8 bajtów.
        for (int i = 0; i < paddedData.length; i += blockLength) {
            // Wyodrębniamy blok 8 bajtów z danych wejściowych (lub zer z paddingu).
            byte[] block = Arrays.copyOfRange(paddedData, i, i + blockLength);

            // Szyfrujemy pojedynczy blok danych.
            cipher.processBlock(block);

            // Wstawiamy zaszyfrowany blok do wynikowej tablicy.
            System.arraycopy(block, 0, encryptedData, i, blockLength);

        }
        // Zwracamy całą zaszyfrowaną tablicę, w tym także bajty z paddingu.
        return encryptedData;
    }


    private static byte[] decrypt(byte[] data, String key) {
        // Blok IDEA to 8 bajtów.
        int blockLength = 8;

        // Tworzymy tablicę, która przechowa odszyfrowane dane.
        byte[] decryptedData = new byte[data.length];

        // Inicjalizujemy szyfr IDEA w trybie deszyfrowania (drugi parametr `false`).
        IdeaCipher cipher = new IdeaCipher(key, false);

        // Przetwarzamy dane blokami po 8 bajtów.
        for (int i = 0; i < data.length; i += blockLength) {
            // Wyodrębniamy blok 8 bajtów z danych zaszyfrowanych.
            byte[] block = Arrays.copyOfRange(data, i, i + blockLength);

            // Odszyfrowujemy pojedynczy blok danych.
            cipher.processBlock(block);

            // Wstawiamy odszyfrowany blok do wynikowej tablicy.
            System.arraycopy(block, 0, decryptedData, i, blockLength);
        }

        // usuwanie paddingu  // Po odszyfrowaniu musimy usunąć padding.
        //    // Wskaźnik na ostatni niezerowy bajt w odszyfrowanych danych.
        int lastNonZeroIndex = decryptedData.length;

        // Cofamy się przez tablicę i szukamy ostatniego niezerowego bajtu.
        while (lastNonZeroIndex > 0 && decryptedData[lastNonZeroIndex - 1] == 0) {
            lastNonZeroIndex--;
        }

        // Tworzymy nową tablicę bez bajtów z paddingu i zwracamy ją.
        return Arrays.copyOf(decryptedData, lastNonZeroIndex);
    }

    public static void main(String[] args) {
        String key = "key";
        String value = "zółć";
        byte[] plaintext = value.getBytes();
        System.out.println("Plaintext: " + Arrays.toString(plaintext));


        byte[] encrypted = encrypt(plaintext, key);
        System.out.println("Encrypted: " + Arrays.toString(encrypted));


        byte[] decrypted = decrypt(encrypted, key);
        System.out.println("Decrypted: " + Arrays.toString(decrypted));
        System.out.println("Decrypted (as string): " + new String(decrypted));
    }
}
