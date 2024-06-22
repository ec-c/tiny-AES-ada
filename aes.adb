package body AES is

   --  Symmetrical operation: same procedure for encrypting as for decrypting.
   --  Note any IV/nonce should never be reused with the same key.
   package body CTR is

      procedure Xcrypt (This : This1_T; Buffer : T_Array) is
      begin
         for Buf in Buffer'Range loop
            null;
         end loop;
      end Xcrypt;

   end CTR;

end AES;
