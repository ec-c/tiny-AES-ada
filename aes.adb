package body AES is

   --  Symmetrical operation: same procedure for encrypting as for decrypting.
   --  Note any IV/nonce should never be reused with the same key.
   package body CTR is

      overriding
      procedure Initialize (This : in out Buffer) is
      begin
         null;
      end Initialize;

      function Xcrypt (This : in out Buffer; Buffer : T_Array) return T_Array is
      begin
         for Buf in Buffer'Range loop
            This.State := Sub_Bytes (@);
         end loop;

         return [];
      end Xcrypt;

   end CTR;

   --  The Sub_Bytes procedure substitutes the values in the state matrix with
   --  values in an S-box.
   function Sub_Bytes (State : State_Array) return State_Array is
      Result : State_Array := State;
   begin
      for I in State'Range (1) loop
         for J in State'Range (2) loop
            Result (I, J) := SBox (T_Index (State (I, J)));
         end loop;
      end loop;

      return Result;
   end Sub_Bytes;

end AES;
