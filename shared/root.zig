pub const types = @import("types.zig");
pub const protocol = @import("protocol.zig");

pub const IpAddress = types.IpAddress;
pub const JailId = types.JailId;
pub const BanState = types.BanState;
pub const Timestamp = types.Timestamp;
pub const Duration = types.Duration;

pub const Command = protocol.Command;
pub const Response = protocol.Response;
pub const serializeCommand = protocol.serializeCommand;
pub const deserializeCommand = protocol.deserializeCommand;
pub const serializeResponse = protocol.serializeResponse;
pub const deserializeResponse = protocol.deserializeResponse;

test {
    _ = types;
    _ = protocol;
}
