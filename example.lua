local json = require("cjson")
local crypt = require("DingTalkCrypto")

local function jsonEncode(data, empty_table_as_object)
    local jsonValue
    if json.encode_empty_table_as_object then
        json.encode_empty_table_as_object(empty_table_as_object or false)
    end
    if require("ffi").os ~= "Windows" then
        json.encode_sparse_array(true)
    end
    pcall(function(d) jsonValue = json.encode(d) end, data)
    return jsonValue
end

local function callback(req, res, next)
    local query = ngx.req.get_uri_args()
    local msg_signature = query.msg_signature
    local timestamp = query.timestamp
    local nonce = query.nonce

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local encryptedData = body.encrypt

    local crypto = crypt:new("TOKEN", "ENCODINGAESKEY", "KEY")

    local data = crypto:getDecryptMsg(msg_signature, timestamp, nonce, encryptedData)
    ngx.log(ngx.ERR, data)

    local t = crypto:getEncryptMsgMap("success", timestamp, nonce)
    res:status("200"):send(jsonEncode(t))
end
