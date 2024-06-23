with Ada.Unchecked_Conversion;

package body AES is

   --  Symmetrical operation: same procedure for encrypting as for decrypting.
   --  Note that an IV/nonce should never be reused with the same key.
   package body CTR is

      overriding
      procedure Initialize (This : in out Buffer) is
      begin
         This.Round_Keys := Key_Expansion (Key);
      end Initialize;

      function Xcrypt (This : in out Buffer; Input : T_Array) return T_Array is
         function To_Word_Array is new Ada.Unchecked_Conversion (T_Array, Word_Array);
         pragma Inline (To_Word_Array);

         State, Result : Word_Array;
      begin
         State := To_Word_Array (Input);
         Result := Cipher (State, This.Round_Keys);

         return [Result (1, 1), Result (1, 2), Result (1, 3), Result (1, 4),
                 Result (2, 1), Result (2, 2), Result (2, 3), Result (2, 4),
                 Result (3, 1), Result (3, 2), Result (3, 3), Result (3, 4),
                 Result (4, 1), Result (4, 2), Result (4, 3), Result (4, 4)];
      end Xcrypt;

   end CTR;

   --  This function creates ten incremental round keys.
   --  The round keys are used in each round to en-/decrypt the states.
   function Key_Expansion (Key : T_Array) return Round_Key_Array is
      Result : Round_Key_Array :=
        --  Initialise the first round by using the key itself.
        [0 => [1 => [Key (1),  Key (2),  Key (3),  Key (4)],
               2 => [Key (5),  Key (6),  Key (7),  Key (8)],
               3 => [Key (9),  Key (10), Key (11), Key (12)],
               4 => [Key (13), Key (14), Key (15), Key (16)]],
         1 .. 10 => [1 .. 4 => [1 .. 4 => 0]]];
   begin
      --  All other round keys are found from the previous round keys.
      for I in 1 .. Round_Key_Array'Last (1) loop
         --  Word 1
         Result (I, 1, 1) := Result (I - 1, 1, 1) xor
            --  RotWord -> SubWord (using Sbox) -> Rcon
            Sbox (T_Index'First + T'Pos (Result (I - 1, 4, 2))) xor Rcon (T_Index (I));
         Result (I, 1, 2) := Result (I - 1, 1, 2) xor
            Sbox (T_Index'First + T'Pos (Result (I - 1, 4, 3)));
         Result (I, 1, 3) := Result (I - 1, 1, 3) xor
            Sbox (T_Index'First + T'Pos (Result (I - 1, 4, 4)));
         Result (I, 1, 4) := Result (I - 1, 1, 4) xor
            Sbox (T_Index'First + T'Pos (Result (I - 1, 4, 1)));

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

   --  The Cipher function is the main function that encrypts the plaintext.
   function Cipher (State : Word_Array; Round_Keys : Round_Key_Array) return Word_Array is
      function Get_Round_Key (R : Natural) return Word_Array is
         K : constant Round_Key_Array := Round_Keys;
      begin
         return [1 => [K (R, 1, 1), K (R, 1, 2), K (R, 1, 3), K (R, 1, 4)],
                 2 => [K (R, 2, 1), K (R, 2, 2), K (R, 2, 3), K (R, 2, 4)],
                 3 => [K (R, 3, 1), K (R, 3, 2), K (R, 3, 3), K (R, 3, 4)],
                 4 => [K (R, 4, 1), K (R, 4, 2), K (R, 4, 3), K (R, 4, 4)]];
      end Get_Round_Key;
      pragma Inline (Get_Round_Key);

      Result : Word_Array := State;
   begin
      --  Add the first round key to the state before starting the rounds.
      Result := Add_Round_Key (Result, Get_Round_Key (0));

      for I in 1 .. 9 loop
         Result := Sub_Bytes (Result);
         Result := Permute (Result);
         Result := Mix_Columns (Result);
         Result := Add_Round_Key (Result, Get_Round_Key (I));
      end loop;

      --  Last round
      Result := Sub_Bytes (Result);
      Result := Permute (Result);
      Result := Add_Round_Key (Result, Get_Round_Key (10));

      return Result;
   end Cipher;

   --  The Sub_Bytes function substitutes the values in the state matrix with
   --  values in an S-box.
   function Sub_Bytes (State : Word_Array) return Word_Array is
      Result : Word_Array;
   begin
      for I in Word_Array'Range (1) loop
         for J in Word_Array'Range (2) loop
            Result (I, J) := Sbox (T_Index'First + T'Pos (State (I, J)));
         end loop;
      end loop;

      return Result;
   end Sub_Bytes;

   --  The Permute function shifts the rows to the left and transposes the matrix.
   function Permute (State : Word_Array) return Word_Array is
   begin
      return [1 => [State (1, 1), State (2, 2), State (3, 3), State (4, 4)],
              2 => [State (2, 1), State (3, 2), State (4, 3), State (1, 4)],
              3 => [State (3, 1), State (4, 2), State (1, 3), State (2, 4)],
              4 => [State (4, 1), State (1, 2), State (2, 3), State (3, 4)]];
   end Permute;

   --  The Mix_Columns functions mixes the rows of the transposed matrix (-> columns).
   function Mix_Columns (State : Word_Array) return Word_Array is
      function Xtime (X : T) return T is
         (Shift_Left (X, 1) xor ((Shift_Right (X, 7) and 1) * 16#1b#));
      pragma Inline (Xtime);

      Result : Word_Array := State;
      A, B, C : T;
   begin
      for I in Word_Array'Range (1) loop
         A := Result (I, 1);
         B := Result (I, 1) xor Result (I, 2) xor Result (I, 3) xor Result (I, 4);

         C := Result (I, 1) xor Result (I, 2);
         C := Xtime (C);
         Result (I, 1) := @ xor C xor B;

         C := Result (I, 2) xor Result (I, 3);
         C := Xtime (C);
         Result (I, 2) := @ xor C xor B;

         C := Result (I, 3) xor Result (I, 4);
         C := Xtime (C);
         Result (I, 3) := @ xor C xor B;

         C := Result (I, 4) xor A;
         C := Xtime (C);
         Result (I, 4) := @ xor C xor B;
      end loop;

      return Result;
   end Mix_Columns;

   --  The Add_Round_Key function adds the round key to the state.
   --  The round key is added to the state by an xor function.
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

end AES;
