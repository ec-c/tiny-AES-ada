with Interfaces;

with Ahven.Framework;

with AES;

package Test_AES is

   type Test_T is new Ahven.Framework.Test_Case with null record;

   subtype u8 is Interfaces.Unsigned_8 range Interfaces.Unsigned_8'Range;
   type Bytes is array (Positive range <>) of aliased u8;

   overriding
   procedure Initialize (Test : in out Test_T);

   procedure Test_1;

end Test_AES;
