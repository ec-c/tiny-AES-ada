package body AES is

   --  Symmetrical operation: same procedure for encrypting as for decrypting.
   --  Note that an IV/nonce should never be reused with the same key.
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

   --  This function creates 10 incremental round keys.
   --  The round keys are used in each round to en-/decrypt the states.
   function Key_Expansion (Key : T_Array) return Round_Key_Array is
      Result : Round_Key_Array :=
        --  Initialise the first round by using the key itself.
        [0 => [Key (1), Key (2), Key (3), Key (4), Key (5), Key (6), Key (7), Key (8),
               Key (9), Key (10), Key (11), Key (12), Key (13), Key (14), Key (15), Key (16)],
         others => [others => 16#ff#]];

      Last_Word : array (1 .. 4) of T;
   begin
      --  All other round keys are found from the previous round keys.
      for I in 1 .. Round_Key_Array'Last (1) loop
         --  RotWord -> SubWord (using Sbox) -> Rcon
         Last_Word :=
           [Sbox (T_Index (Result (I - 1, 14)) + 1) xor Rcon (T_Index (I)),
            Sbox (T_Index (Result (I - 1, 15)) + 1),
            Sbox (T_Index (Result (I - 1, 16)) + 1),
            Sbox (T_Index (Result (I - 1, 13)) + 1)];

         --  Word 1
         Result (I, 1) := Result (I - 1, 1) xor Last_Word (1);
         Result (I, 2) := Result (I - 1, 2) xor Last_Word (2);
         Result (I, 3) := Result (I - 1, 3) xor Last_Word (3);
         Result (I, 4) := Result (I - 1, 4) xor Last_Word (4);

         --  Word 2
         Result (I, 5) := Result (I - 1, 5) xor Result (I, 1);
         Result (I, 6) := Result (I - 1, 6) xor Result (I, 2);
         Result (I, 7) := Result (I - 1, 7) xor Result (I, 3);
         Result (I, 8) := Result (I - 1, 8) xor Result (I, 4);

         --  Word 3
         Result (I, 9)  := Result (I - 1, 9)  xor Result (I, 5);
         Result (I, 10) := Result (I - 1, 10) xor Result (I, 6);
         Result (I, 11) := Result (I - 1, 11) xor Result (I, 7);
         Result (I, 12) := Result (I - 1, 12) xor Result (I, 8);

         --  Word 4
         Result (I, 13) := Result (I - 1, 13) xor Result (I, 9);
         Result (I, 14) := Result (I - 1, 14) xor Result (I, 10);
         Result (I, 15) := Result (I - 1, 15) xor Result (I, 11);
         Result (I, 16) := Result (I - 1, 16) xor Result (I, 12);
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
            Result (I, J) := Sbox (T_Index (State (I, J)));
         end loop;
      end loop;

      return Result;
   end Sub_Bytes;

end AES;
