local aes = require "resty.nettle.aes"
local str = require "resty.string"
local restySha1    = require "resty.sha1"
local bs64decode    = ngx.decode_base64
local bs64encode    = ngx.encode_base64

local ffi = require "ffi"
local C = ffi.C

ffi.cdef[[
uint32_t ntohl(uint32_t netlong);
uint32_t htonl(uint32_t netlong);
]]

local DingTalkCrypto = {}
DingTalkCrypto.__index = DingTalkCrypto

function DingTalkCrypto:new(token, encodingAESKey, suiteKey)
    local c = setmetatable({}, DingTalkCrypto)
    if #encodingAESKey ~= 43 then
        error("Invalid EncodingAESKey")
    end
    local aesKey, err = bs64decode(encodingAESKey .. "=")
    if err then
        error(err)
    end

    c.token = token
    c.encodingAESKey = encodingAESKey
    c.suiteKey = suiteKey
    c.aesKey = aesKey
    return c
end

function DingTalkCrypto:sha1(content)
    local sha = restySha1:new()
    if not sha then
        error("failed to create the sha1 object")
    end
    local ok = sha:update(content)
    if not ok then
        error("failed to update data")
    end

    local digest = sha:final()
    return digest
end

function DingTalkCrypto:decryptMsg(msg)
    local decodeMsg = bs64decode(msg)
    local cbc, err = aes.new(self.aesKey, "cbc", string.sub(self.aesKey, 1, 16))
    if err then
        error(err)
    end
    local allMsg = cbc:decrypt(decodeMsg)
    if not allMsg or #allMsg<=20 then
        error("invalid msg len "..allMsg)
    end
    local msgLen = string.sub(allMsg, 17, 20)
    msgLen = ffi.cast("uint32_t&" ,msgLen)
    local dataLen = C.ntohl(msgLen)
    --key = string.sub(allMsg, 21 + data_len, -1)
    return string.sub(allMsg, 21, 20 + dataLen)
end

local function intToBytes(intValue)
    local bytes = ""
    for i = 1, 4 do
        local byte = string.char(intValue % 256)
        bytes = byte .. bytes
        intValue = math.floor(intValue / 256)
    end
    return bytes
end

function DingTalkCrypto:encryptMsg(content)
    local randMsg = self:randomString(16)
    content =  randMsg.. intToBytes(#content).. content .. self.suiteKey
    local cbc = aes.new(self.aesKey, "cbc", string.sub(self.aesKey, 1, 16))
    return  bs64encode(cbc:encrypt(content)):gsub("\n", ""):gsub("\r", "")
end

function DingTalkCrypto:getDecryptMsg(signature, timestamp, nonce, secretMsg)
    if not self:verificationSignature(self.token, timestamp, nonce, secretMsg, signature) then
        error("Signature does not match")
    end
    return self:decryptMsg(secretMsg)
end

function DingTalkCrypto:genSignature(nonce, timestamp, token, msg)
    local arr = {nonce, timestamp, token, msg}
    table.sort(arr)
    return str.to_hex(self:sha1( table.concat(arr)))
end

function DingTalkCrypto:getEncryptMsgMap(content, timestamp, nonce)
    content = self:encryptMsg(content)
    local sign = self:genSignature(nonce, timestamp, self.token, content)
    return {msg_signature=sign, encrypt= content, timeStamp= timestamp, nonce= nonce}
end

function DingTalkCrypto:verificationSignature(token, timestamp, nonce, secretMsg, signature)
    local array = {token, timestamp, nonce, secretMsg}
    table.sort(array)
    local sign = self:genSignature(nonce, timestamp, token, secretMsg)
    return sign == signature
end

function DingTalkCrypto:randomString(n)
    local result = {}
    for i=1, n do
        table.insert(result, string.char(math.random(0, 255)))
    end
    return table.concat(result)
end

return DingTalkCrypto
