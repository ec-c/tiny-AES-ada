with Interfaces;

with Ahven.Framework;

package Test_AES is

   type Test_T is new Ahven.Framework.Test_Case with null record;

   subtype u8 is Interfaces.Unsigned_8 range Interfaces.Unsigned_8'Range;
   type Bytes is array (Positive range <>) of aliased u8;

   subtype u64 is Interfaces.Unsigned_64 range Interfaces.Unsigned_64'Range;

   overriding
   procedure Initialize (Test : in out Test_T);

   procedure Test_AES128_ECB_Encrypt_Test_Vector_1;
   procedure Test_AES128_ECB_Encrypt_Test_Vector_2;
   procedure Test_AES128_ECB_Encrypt_Test_Vector_3;
   procedure Test_AES128_ECB_Encrypt_Test_Vector_4;

   procedure Test_AES128_CTR_Test_Vector_1;
   procedure Test_AES128_CTR_Test_Vector_2;
   procedure Test_AES128_CTR_Test_Vector_3;
   procedure Test_AES128_CTR_Test_Vector_4;

end Test_AES;
