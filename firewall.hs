import Text.Printf

type IPTablesArg = String
type IPTablesCmd = String

data IPTablesChain = Input
                   | Output
                   | Forward

instance Show IPTablesChain where
    show Input   = "INPUT"
    show Output  = "OUTPUT"
    show Forward = "FORWARD"

data IPTablesAction = Accept
                    | Drop
                    | Queue
                    | Return

instance Show IPTablesAction where
    show Accept = "ACCEPT"
    show Drop   = "DROP"
    show Queue  = "QUEUE"
    show Return = "RETURN"

data Protocol = TCP
              | UDP
              | ICMP

instance Show Protocol where
    show TCP  = "tcp"
    show UDP  = "udp"
    show ICMP = "icmp"

data ConnectionState = New
                     | Invalid
                     | Est_Rel

instance Show ConnectionState where
    show New     = "NEW"
    show Invalid = "INVALID"
    show Est_Rel = "ESTABLISHED,RELATED"

-- Policy Handling
setChainPolicy :: IPTablesChain -> IPTablesAction -> IPTablesArg
setChainPolicy chain action = printf "-P %s %s" (show chain) (show action)

-- Chain modification
chainAppend :: IPTablesChain -> IPTablesArg
chainAppend chain   = printf "-A %s" (show chain)

dport :: Protocol -> Integer -> IPTablesArg
dport proto port = printf "-p %s --dport %d --syn" (show proto) port

trackConnState :: ConnectionState -> IPTablesArg
trackConnState state = printf "-m conntrack --ctstate %s" (show state)

logPacket :: String -> IPTablesArg
logPacket logPrefix = printf "-j LOG --log-prefix \"%s\" --log-ip-options --log-tcp-options" logPrefix

jumpTo :: IPTablesAction -> IPTablesArg
jumpTo target = printf "-j %s" (show target)


-- Generate Commands
mkIptablesCmd :: [IPTablesArg] -> IPTablesCmd
mkIptablesCmd cmds = foldl (\x y -> x ++ " " ++ y) "iptables" cmds

-- Lazy Macros
openPorts :: IPTablesChain -> [(Protocol, Integer)] -> [[IPTablesArg]]
openPorts _ [] = []
openPorts chain ((proto,port):xs) = [chainAppend chain, trackConnState New, dport proto port] : openPorts chain xs

-- Protocol / Port Specfication
ftp     = (TCP, 21)
ssh     = (TCP, 22)
smtp    = (TCP, 25)
whois   = (TCP, 43)
dns1    = (TCP, 53)
dns2    = (UDP, 53)
http    = (TCP, 80)
https   = (TCP, 443)
rsync   = (TCP, 873)
rwhois1 = (TCP, 4321)
rwhois2 = (UDP, 4321)

--------------------------------------------------------------------------------
-- Firewall Definitions
--------------------------------------------------------------------------------
inputChain = [ [setChainPolicy Input Drop]
             , [chainAppend Input, trackConnState Invalid, logPacket "(IN)DROP INVALID"]
             , [chainAppend Input, trackConnState Invalid, jumpTo Drop]
             , [chainAppend Input, trackConnState Est_Rel, jumpTo Accept]
             , [chainAppend Input, "-i lo", jumpTo Accept]
             , [chainAppend Input, logPacket "(IN)DROP "]
             ]

outputChain = [ [setChainPolicy Output Drop]
              , [chainAppend Output, trackConnState Invalid, logPacket "(OUT)DROP INVALID "]
              , [chainAppend Output, trackConnState Invalid, jumpTo Drop]
              , [chainAppend Output, trackConnState Est_Rel, jumpTo Accept]
              , [chainAppend Output, "-p icmp --icmp-type echo-request", jumpTo Accept]
              ] ++
              openPorts Output [ftp, ssh, smtp, whois, dns1, dns2, http, https, rsync, rwhois1, rwhois2]
              ++ [[chainAppend Output, logPacket "(OUT)DROP "]]

forwardChain = [ [setChainPolicy Forward Drop] ]

--------------------------------------------------------------------------------
-- Main Function
--------------------------------------------------------------------------------
main :: IO()
main = do putStrLn rules where
    rules  = unlines $ map mkIptablesCmd $ inputChain ++ outputChain ++ forwardChain
