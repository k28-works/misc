@set "args=%*"
@powershell "iex((@('')*3+(cat '%~f0'|select -skip 3))-join[char]10)"
@exit /b %ERRORLEVEL%

function totp {
    Param(
        [string]$Key,
        [int]$Digit = 6,
        [int]$TimeStep = 30
    )
    $counter = [Math]::Floor(
        ((Get-Date) - (Get-Date("1970/1/1 0:0:0 GMT"))).TotalSeconds / $TimeStep
    )
    return hotp $Key $Digit $counter
}
function hotp {
    Param(
        [string]$Key,
        [int]$Digit = 6,
        [int]$Counter
    )
    $digest = hmacsha1 $Key $Counter
    return truncate $digest $Digit
}
function hmacsha1 {
    Param([string]$Key, [int]$Counter)
    $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
    $hmac.key = base32decode $Key
    $message = [BitConverter]::GetBytes([Convert]::ToInt64($Counter))
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($message)
    }
    return $hmac.ComputeHash($message)
}
function truncate {
    Param([byte[]]$Data, [int]$Digit)
    $offset = $Data[($Data.Length - 1)] -band 0x0F
    $code = $Data[$offset..($offset + 4)]
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($code)
    }
    $code = ("0" * $Digit) + [string]([BitConverter]::ToInt32($code, 0) -band 0x7FFFFFFF)
    return $code.SubString($code.Length - $Digit)
}
function base32decode {
    Param([string]$Source)
    $Source = $Source.ToUpper()
    $decode = @{
        "A" = ([Convert]::ToString(0, 2).PadLeft(5, "0"))
        "B" = ([Convert]::ToString(1, 2).PadLeft(5, "0"))
        "C" = ([Convert]::ToString(2, 2).PadLeft(5, "0"))
        "D" = ([Convert]::ToString(3, 2).PadLeft(5, "0"))
        "E" = ([Convert]::ToString(4, 2).PadLeft(5, "0"))
        "F" = ([Convert]::ToString(5, 2).PadLeft(5, "0"))
        "G" = ([Convert]::ToString(6, 2).PadLeft(5, "0"))
        "H" = ([Convert]::ToString(7, 2).PadLeft(5, "0"))
        "I" = ([Convert]::ToString(8, 2).PadLeft(5, "0"))
        "J" = ([Convert]::ToString(9, 2).PadLeft(5, "0"))
        "K" = ([Convert]::ToString(10, 2).PadLeft(5, "0"))
        "L" = ([Convert]::ToString(11, 2).PadLeft(5, "0"))
        "M" = ([Convert]::ToString(12, 2).PadLeft(5, "0"))
        "N" = ([Convert]::ToString(13, 2).PadLeft(5, "0"))
        "O" = ([Convert]::ToString(14, 2).PadLeft(5, "0"))
        "P" = ([Convert]::ToString(15, 2).PadLeft(5, "0"))
        "Q" = ([Convert]::ToString(16, 2).PadLeft(5, "0"))
        "R" = ([Convert]::ToString(17, 2).PadLeft(5, "0"))
        "S" = ([Convert]::ToString(18, 2).PadLeft(5, "0"))
        "T" = ([Convert]::ToString(19, 2).PadLeft(5, "0"))
        "U" = ([Convert]::ToString(20, 2).PadLeft(5, "0"))
        "V" = ([Convert]::ToString(21, 2).PadLeft(5, "0"))
        "W" = ([Convert]::ToString(22, 2).PadLeft(5, "0"))
        "X" = ([Convert]::ToString(23, 2).PadLeft(5, "0"))
        "Y" = ([Convert]::ToString(24, 2).PadLeft(5, "0"))
        "Z" = ([Convert]::ToString(25, 2).PadLeft(5, "0"))
        "2" = ([Convert]::ToString(26, 2).PadLeft(5, "0"))
        "3" = ([Convert]::ToString(27, 2).PadLeft(5, "0"))
        "4" = ([Convert]::ToString(28, 2).PadLeft(5, "0"))
        "5" = ([Convert]::ToString(29, 2).PadLeft(5, "0"))
        "6" = ([Convert]::ToString(30, 2).PadLeft(5, "0"))
        "7" = ([Convert]::ToString(31, 2).PadLeft(5, "0"))
    }
    $result = @()
    for ($i = 0; $i -lt $Source.Length; $i += 8) {
        $line = ""
        for ($j = 0; $j -lt 8; $j++) {
            $line += $decode[[string]$Source[$i + $j]]
        }
        $line = $line.PadRight(40, "0")
        for ($j = 0; $j -lt 40; $j += 8) {
            $result += [Convert]::ToInt32($line.SubString($j, 8), 2)
        }
    }
    return $result
}

iex ("totp "+$env:args)

## EOF ##
