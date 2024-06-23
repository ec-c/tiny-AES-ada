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
        [0 => [1 => [Key (1), Key (2), Key (3), Key (4)],
               2 => [Key (5), Key (6), Key (7), Key (8)],
               3 => [Key (9), Key (10), Key (11), Key (12)],
               4 => [Key (13), Key (14), Key (15), Key (16)]],
         1 .. 10 => [1 .. 4 => [1 .. 4 => 0]]];
   begin
      --  All other round keys are found from the previous round keys.
      for I in 1 .. Round_Key_Array'Last (1) loop
         --  RotWord -> SubWord (using Sbox) -> Rcon
         --  Word 1
         Result (I, 1, 1) := Result (I - 1, 1, 1) xor
            Sbox (T_Index (Result (I - 1, 4, 2)) + 1) xor Rcon (T_Index (I));
         Result (I, 1, 2) := Result (I - 1, 1, 2) xor
            Sbox (T_Index (Result (I - 1, 4, 3)) + 1);
         Result (I, 1, 3) := Result (I - 1, 1, 3) xor
            Sbox (T_Index (Result (I - 1, 4, 4)) + 1);
         Result (I, 1, 4) := Result (I - 1, 1, 4) xor
            Sbox (T_Index (Result (I - 1, 4, 1)) + 1);

         --  Word 2
         Result (I, 2, 1) := Result (I - 1, 2, 1) xor Result (I, 1, 1);
         Result (I, 2, 2) := Result (I - 1, 2, 2) xor Result (I, 1, 2);
         Result (I, 2, 3) := Result (I - 1, 2, 3) xor Result (I, 1, 3);
         Result (I, 2, 4) := Result (I - 1, 2, 4) xor Result (I, 1, 4);

         --  Word 3
         Result (I, 3, 1) := Result (I - 1, 3, 1) xor Result (I, 2, 1);
         Result (I, 3, 2) := Result (I - 1, 3, 2) xor Result (I, 2, 2);
         Result (I, 3, 3) := Result (I - 1, 3, 3) xor Result (I, 2, 3);
         Result (I, 3, 4) := Result (I - 1, 3, 4) xor Result (I, 2, 4);

         --  Word 4
         Result (I, 4, 1) := Result (I - 1, 4, 1) xor Result (I, 3, 1);
         Result (I, 4, 2) := Result (I - 1, 4, 2) xor Result (I, 3, 2);
         Result (I, 4, 3) := Result (I - 1, 4, 3) xor Result (I, 3, 3);
         Result (I, 4, 4) := Result (I - 1, 4, 4) xor Result (I, 3, 4);
      end loop;

      return Result;
   end Key_Expansion;

   --  The Add_Round_Key function adds the round key to the state.
   --  The round key is added to the state by an XOR function.
   function Add_Round_Key (State : Word_Array; Round_Key : Word_Array) return Word_Array is
      Result : Word_Array;
   begin
      for I in Word_Array'Range (1) loop
         for J in Word_Array'Range (2) loop
            Result (I, J) := State (I, J) xor Round_Key (I, J);
         end loop;
      end loop;

      return Result;
   end Add_Round_Key;

   --  The Sub_Bytes function substitutes the values in the state matrix with
   --  values in an S-box.
   function Sub_Bytes (State : Word_Array) return Word_Array is
      Result : Word_Array;
   begin
      for I in Word_Array'Range (1) loop
         for J in Word_Array'Range (2) loop
            Result (I, J) := Sbox (T_Index (State (I, J)) + 1);
         end loop;
      end loop;

      return Result;
   end Sub_Bytes;

   --  The Shift_Rows function shifts the rows in the state to the left.
   --  Each row is shifted with by different offset:
   --    * first row: not shifted
   --    * second row: shifted to the left by 1 byte
   --    * third row: shifted to the left by 2 bytes
   --    * fourth row: shifted to the left by 3 bytes
   function Shift_Rows (State : Word_Array) return Word_Array is
   begin
      return [1 => [State (1, 1), State (1, 2), State (1, 3), State (1, 4)],
              2 => [State (2, 2), State (2, 3), State (2, 4), State (2, 1)],
              3 => [State (3, 3), State (3, 4), State (3, 1), State (3, 2)],
              4 => [State (4, 4), State (4, 1), State (4, 2), State (4, 3)]];
   end Shift_Rows;

   --  The Mix_Columns functions mixes the columns of the state matrix.
   --  TODO: rename variables
   function Mix_Columns (State : Word_Array) return Word_Array is
      function Xtime (X : T) return T is
         (Shift_Left (X, 1) xor ((Shift_Right (X, 7) and 1) * 16#1b#));
      pragma Inline (Xtime);

      Result : Word_Array;
      Tmp, Tm, T1 : T;
   begin
      for I in Word_Array'Range loop
         T1 := State (I, 1);
         Tmp := State (I, 1) xor State (I, 2) xor State (I, 3) xor State (I, 4);
         Tm := State (I, 1) xor State (I, 2);

         Tm := State (I, 2) xor State (I, 3);
         Tm := Xtime (Tm);
         Result (I, 2) := @ xor Tm xor Tmp;

         Tm := State (I, 3) xor State (I, 4);
         Tm := Xtime (Tm);
         Result (I, 3) := @ xor Tm xor Tmp;

         Tm := State (I, 4) xor T1;
         Tm := Xtime (Tm);
         Result (I, 4) := @ xor Tm xor Tmp;
      end loop;

      return Result;
   end Mix_Columns;

end AES;
