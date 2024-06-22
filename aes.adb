package body AES is

   --  Symmetrical operation: same procedure for encrypting as for decrypting.
   --  Note any IV/nonce should never be reused with the same key.
   package body CTR is

      overriding
      procedure Initialize (This : in out Buffer) is
      begin
         This.Round_Keys := Key_Expansion (Key);
      end Initialize;

      function Xcrypt (This : in out Buffer; Buffer : T_Array) return T_Array is
      begin
         for Buf in Buffer'Range loop
            This.State := Sub_Bytes (@);
         end loop;

         return [];
      end Xcrypt;

   end CTR;

   function Key_Expansion (Key : T_Array) return Round_Key_Array is
      Result : Round_Key_Array;
   begin
      for I in Round_Key_Array'Range (1) loop
         null;
      end loop;

      return Result;
   end Key_Expansion;

   --  The Sub_Bytes procedure substitutes the values in the state matrix with
   --  values in an S-box.
   function Sub_Bytes (State : State_Array) return State_Array is
      Result : State_Array := State;
   begin
      for I in State_Array'Range (1) loop
         for J in State_Array'Range (2) loop
            Result (I, J) := SBox (T_Index (State (I, J)));
         end loop;
      end loop;

      return Result;
   end Sub_Bytes;

end AES;
