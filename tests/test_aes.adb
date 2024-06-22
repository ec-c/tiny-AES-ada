with Ahven;

package body Test_AES is
   use Ahven;

   overriding
   procedure Initialize (Test : in out Test_T) is
   begin
      Set_Name (Test, "AES");

      Ahven.Framework.Add_Test_Routine (Test, Test_1'Access, "test 1");
   end Initialize;

   procedure Test_1 is
   begin
      Assert (1 = 2, "fail");
   end Test_1;

end Test_AES;
