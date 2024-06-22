with Ahven.Framework;
with Ahven.Text_Runner;

with Test_AES;

procedure Tester is
   Suite : Ahven.Framework.Test_Suite := Ahven.Framework.Create_Suite ("All");
begin
   Ahven.Framework.Add_Test (Suite, new Test_AES.Test_T);

   Ahven.Text_Runner.Run (Suite);
end Tester;
