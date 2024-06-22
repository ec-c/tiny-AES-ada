with Interfaces;

with Ahven.Framework;

package Test_AES is

   type Test_T is new Ahven.Framework.Test_Case with null record;

   subtype u8 is Interfaces.Unsigned_8 range Interfaces.Unsigned_8'Range;
   type Bytes is array (Positive range <>) of aliased u8;

   overriding
   procedure Initialize (Test : in out Test_T);

   procedure Test_AES128_Encrypt_CTR_1;
   procedure Test_AES128_Encrypt_CTR_2;

end Test_AES;
