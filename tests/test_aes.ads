with Ahven.Framework;

package Test_AES is

   type Test_T is new Ahven.Framework.Test_Case with null record;

   overriding
   procedure Initialize (Test : in out Test_T);

   procedure Test_1;

end Test_AES;
