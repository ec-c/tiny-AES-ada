package body AES is

   package body ECB is

      procedure Encrypt (This : This_T; Buffer : T_Array) is
      begin
         null;
      end Encrypt;

      procedure Decrypt (This : This_T; Buffer : T_Array) is
      begin
         null;
      end Decrypt;

   end ECB;

   package body CBC is

      procedure Encrypt (This : This_T; Buffer : T_Array) is
      begin
         null;
      end Encrypt;

      procedure Decrypt (This : This_T; Buffer : T_Array) is
      begin
         null;
      end Decrypt;

   end CBC;

   package body CTR is

      procedure Xcrypt (This : This_T; Buffer : T_Array) is
      begin
         null;
      end Xcrypt;

   end CTR;

   procedure Cipher (This : This_T; Round_Key : T) is
   begin
      This.Add_Round_Key (1, Round_Key);
   end Cipher;

   procedure Add_Round_Key (This : This_T; Round : Positive; Round_Key : T) is
   begin
      null;
   end Add_Round_Key;

   --  The Sub_Bytes procedure substitutes the values in the state matrix with
   --  values in an S-box.
   procedure Sub_Bytes (This : in out This_T) is
   begin
      for I in This.State'Range (1) loop
         for J in This.State'Range (2) loop
            This.State (I, J) := Forward_SBox (T_Index (This.State (I, J)));
         end loop;
      end loop;
   end Sub_Bytes;

   --  The Shift_Rows procedure shifts the rows in the state to the left.
   --  Each row is shifted with different offset.
   --  Offset = Row number. So the first row is not shifted.
   procedure Shift_Rows (This : in out This_T) is
      Temp : T;
   begin
      --  Rotate the second row to the left by 1 column.
      Temp              := This.State (1, 2);
      This.State (1, 2) := This.State (2, 2);
      This.State (2, 2) := This.State (3, 2);
      This.State (3, 2) := This.State (4, 2);
      This.State (4, 2) := Temp;

      --  Rotate the third row to the left by 2 columns.
      Temp              := This.State (1, 3);
      This.State (2, 3) := This.State (4, 3);
      This.State (3, 3) := Temp;

      Temp              := This.State (2, 3);
      This.State (2, 3) := This.State (4, 3);
      This.State (4, 3) := Temp;

      --  Rotate the fourth row to the left by 3 columns.
      Temp              := This.State (1, 4);
      This.State (1, 4) := This.State (4, 4);
      This.State (4, 4) := This.State (3, 4);
      This.State (3, 4) := This.State (2, 4);
      This.State (2, 4) := Temp;
   end Shift_Rows;

   procedure Mix_Columns (This : This_T) is
   begin
      null;
   end Mix_Columns;

end AES;
