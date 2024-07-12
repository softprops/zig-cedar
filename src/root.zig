// see also syntax-policy.html
// parser inspired  by https://notes.eatonphil.com/zigrocks-sql.html
const std = @import("std");
const testing = std.testing;

const Token = struct {
    const Kind = enum {
        // keywords
        permit,
        forbid,
        principal,
        @"?principal",
        action,
        resource,
        @"?resource",

        in,

        // conditions
        when,
        unless,
        @"if",
        then,
        @"else",

        // syntax
        left_paren,
        right_paren,
        semicolon,
        comma,
        path_separator,
        list_open,
        list_close,

        // literals
        lit_true,
        lit_false,

        // relop
        eq,

        ident,
        string,
    };

    start: u64,
    end: u64,
    kind: Kind,
    source: []const u8,

    pub fn value(self: @This()) []const u8 {
        return self.source[self.start..self.end];
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{s} ('{s}')", .{ @tagName(self.kind), self.value() });
    }

    fn debug(self: @This(), msg: []const u8) void {
        var line: usize = 0;
        var column: usize = 0;
        var lineStartIndex: usize = 0;
        var lineEndIndex: usize = 0;
        var i: usize = 0;
        var source = self.source;
        while (i < source.len) {
            if (source[i] == '\n') {
                line = line + 1;
                column = 0;
                lineStartIndex = i;
            } else {
                column = column + 1;
            }

            if (i == self.start) {
                // Find the end of the line
                lineEndIndex = i;
                while (source[lineEndIndex] != '\n') {
                    lineEndIndex = lineEndIndex + 1;
                }
                break;
            }

            i = i + 1;
        }

        std.debug.print(
            "{s}\nNear line {}, column {}.\n{s}\n",
            .{ msg, line + 1, column, source[lineStartIndex..lineEndIndex] },
        );
        while (column - 1 > 0) {
            std.debug.print(" ", .{});
            column = column - 1;
        }
        std.debug.print("^ Near here\n\n", .{});
    }
};

fn debug(tokens: []Token, preferredIndex: usize, msg: []const u8) void {
    var i = preferredIndex;
    while (i >= tokens.len) {
        i = i - 1;
    }

    tokens[i].debug(msg);
}

const Builtin = struct {
    name: []const u8,
    kind: Token.Kind,
};

// order longest to shortest as a parser optimization
const BUILTINS = [_]Builtin{
    // keywords
    .{ .name = "principal", .kind = .principal },
    .{ .name = "resource", .kind = .resource },
    .{ .name = "permit", .kind = .permit },
    .{ .name = "forbid", .kind = .forbid },
    .{ .name = "action", .kind = .action },
    .{ .name = "?principal", .kind = .@"?principal" },
    .{ .name = "?resource", .kind = .@"?resource" },

    .{ .name = "in", .kind = .in },
    .{ .name = "::", .kind = .path_separator },

    // relop
    .{ .name = "==", .kind = .eq },

    // syntax
    .{ .name = "[", .kind = .list_open },
    .{ .name = "]", .kind = .list_close },
    .{ .name = "(", .kind = .left_paren },
    .{ .name = ")", .kind = .right_paren },
    .{ .name = ",", .kind = .comma },
    .{ .name = ";", .kind = .semicolon },
};

/// https://notes.eatonphil.com/zigrocks-sql.html
fn lex(source: []const u8, tokens: *std.ArrayList(Token)) !void {
    var i: usize = 0;
    while (i < source.len) {
        i = skip(source, i);
        if (i >= source.len) {
            break;
        }

        const keywordRes = lexKeyword(source, i);
        if (keywordRes.token) |token| {
            tokens.append(token) catch return error.OOM;
            i = keywordRes.nextPosition;
            continue;
        }

        const stringRes = lexString(source, i);
        if (stringRes.token) |token| {
            tokens.append(token) catch return error.OOM;
            i = stringRes.nextPosition;
            continue;
        }

        const identifierRes = lexIdent(source, i);
        if (identifierRes.token) |token| {
            tokens.append(token) catch return error.OOM;
            i = identifierRes.nextPosition;
            continue;
        }

        if (tokens.items.len > 0) {
            debug(tokens.items, tokens.items.len - 1, "Last good token.\n");
        }
        return error.BadToken;
    }
}

fn lexKeyword(source: []const u8, index: usize) struct { nextPosition: usize, token: ?Token } {
    var longestLen: usize = 0;
    var kind: Token.Kind = .permit;
    for (BUILTINS) |builtin| {
        if (index + builtin.name.len > source.len) {
            continue;
        }

        if (std.mem.eql(u8, source[index .. index + builtin.name.len], builtin.name)) {
            longestLen = builtin.name.len;
            kind = builtin.kind;
            // First match is the longest match
            break;
        }
    }

    if (longestLen == 0) {
        return .{ .nextPosition = 0, .token = null };
    }

    return .{
        .nextPosition = index + longestLen,
        .token = Token{
            .source = source,
            .start = index,
            .end = index + longestLen,
            .kind = kind,
        },
    };
}

fn lexString(source: []const u8, index: usize) struct { nextPosition: usize, token: ?Token } {
    var i = index;
    if (source[i] != '\"') {
        return .{ .nextPosition = 0, .token = null };
    }
    i = i + 1;

    const start = i;
    var end = i;
    while (source[i] != '\"') {
        end = end + 1;
        i = i + 1;
    }

    if (source[i] == '\"') {
        i = i + 1;
    }

    if (start == end) {
        return .{ .nextPosition = 0, .token = null };
    }

    return .{
        .nextPosition = i,
        .token = Token{
            .source = source,
            .start = start,
            .end = end,
            .kind = .string,
        },
    };
}

fn lexIdent(source: []const u8, index: usize) struct { nextPosition: usize, token: ?Token } {
    const start = index;
    var end = index;
    var i = index;
    while ((source[i] >= 'a' and source[i] <= 'z') or
        (source[i] >= 'A' and source[i] <= 'Z') or
        (source[i] == '*'))
    {
        end = end + 1;
        i = i + 1;
    }

    if (start == end) {
        return .{ .nextPosition = 0, .token = null };
    }

    return .{
        .nextPosition = end,
        .token = Token{
            .source = source,
            .start = start,
            .end = end,
            .kind = .ident,
        },
    };
}

// skip whitespace,new lines, and commands
fn skip(source: []const u8, index: usize) usize {
    var next = index;
    while (source[next] == ' ' or
        source[next] == '\n' or
        source[next] == '\t' or
        source[next] == '\r')
    {
        next = next + 1;
        if (next == source.len) {
            break;
        }
    }

    if (source[next] == '/') {
        if (next + 1 != source.len and source[next + 1] == '/') {
            next = next + 2;
            while (source[next] != '\n' and next != source.len) {
                next = next + 1;
            }
        }
    }

    return next;
}

// parsing

pub const EntityUID = struct {
    ty: []const u8,
    id: []const u8,
    fn init(ty: []const u8, id: []const u8) @This() {
        return .{ .ty = ty, .id = id };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{s}::\"{s}\"", .{ self.ty, self.id });
    }
};

pub const Ref = union(enum) {
    id: EntityUID,
    slot: void,

    fn slot() @This() {
        return .{ .slot = {} };
    }

    fn id(eid: EntityUID) @This() {
        return .{ .id = eid };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .id => |v| try writer.print("{s}", .{v}),
            .slot => try writer.print("<slot>", .{}),
        }
    }
};

pub const Scope = struct {
    principal: Principal,
    action: Action,
    resource: Resource,
    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("({s},{s},{s})", .{ self.principal, self.action, self.resource });
    }
};

pub const Principal = union(enum) {
    any: void,
    in: Ref,
    eq: Ref,
    is: []const u8,
    //isIn:
    fn any() @This() {
        return .{ .any = {} };
    }
    fn in(ref: Ref) @This() {
        return .{ .in = ref };
    }
    fn eq(ref: Ref) @This() {
        return .{ .in = ref };
    }
    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .any => try writer.print("principal", .{}),
            .in => |v| try writer.print("principal in {s}", .{v}),
            .eq => |v| try writer.print("principal == {s}", .{v}),
            .is => |v| try writer.print("principal is {s}", .{v}),
        }
    }
};

pub const Action = union(enum) {
    any: void,
    in: Ref,
    eq: Ref,
    is: []const u8,
    //isIn:
    fn any() @This() {
        return .{ .any = {} };
    }

    fn in(ref: Ref) @This() {
        return .{ .in = ref };
    }
    fn eq(ref: Ref) @This() {
        return .{ .in = ref };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .any => try writer.print("action", .{}),
            .in => |v| try writer.print("action in {s}", .{v}),
            .eq => |v| try writer.print("action == {s}", .{v}),
            .is => |v| try writer.print("action is {s}", .{v}),
        }
    }
};

pub const Resource = union(enum) {
    any: void,
    in: Ref,
    eq: Ref,
    is: []const u8,
    //isIn:

    fn any() @This() {
        return .{ .any = {} };
    }
    fn in(ref: Ref) @This() {
        return .{ .in = ref };
    }
    fn eq(ref: Ref) @This() {
        return .{ .in = ref };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .any => try writer.print("resource", .{}),
            .in => |v| try writer.print("resource in {s}", .{v}),
            .eq => |v| try writer.print("resource == {s}", .{v}),
            .is => |v| try writer.print("resource is {s}", .{v}),
        }
    }
};

pub const Effect = enum { forbid, permit };

pub const Policy = struct {
    // todo annotations
    effect: Effect,
    scope: Scope,
    // todo conditions

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{s}{s};", .{ @tagName(self.effect), self.scope });
    }
};

pub const PolicySet = struct {
    allocator: std.mem.Allocator,
    policies: []const Policy,
    fn init(allocator: std.mem.Allocator, policies: []const Policy) @This() {
        return .{ .allocator = allocator, .polcies = policies };
    }
    fn deinit(self: *@This()) void {
        self.allocator.free(self.policies);
    }
};

/// parse a set of policies from a string
pub fn parsePolcies(allocator: std.mem.Allocator, source: []const u8) !PolicySet {
    var tokens = std.ArrayList(Token).init(allocator);
    defer tokens.deinit();
    try lex(source, &tokens);
    const slice = try tokens.toOwnedSlice();
    defer allocator.free(slice);
    return try parse(allocator, slice);
}

fn parse(allocator: std.mem.Allocator, tokens: []Token) !PolicySet {
    var policies = std.ArrayList(Policy).init(allocator);
    defer policies.deinit();
    var i: usize = 0;

    while (i < tokens.len) {
        // Policy ::= {Annotation} Effect '(' Scope ')' {Conditions} ';'

        // Effect ::= 'permit' | 'forbid'
        const forbid = matches(tokens, i, .forbid);
        const permit = matches(tokens, i, .permit);
        if (!forbid and !permit) {
            return error.ExpectedEffect;
        }
        i = i + 1;

        if (!matches(tokens, i, .left_paren)) {
            return error.ExpectedOpenParen;
        }
        i = i + 1;

        //  Scope ::= Principal ',' Action ',' Resource

        // Principal ::= 'principal' [(['is' PATH] ['in' (Entity | '?principal')]) | ('==' (Entity | '?principal'))]
        if (!matches(tokens, i, .principal)) {
            return error.ExpectedPricipal;
        }
        i = i + 1;

        var principal = Principal.any();

        if (matches(tokens, i, .in)) {
            i = i + 1;
            if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                principal = Principal.in(
                    Ref.id(entity.entity),
                );
            } else if (matches(tokens, i, .@"?principal")) {
                i = i + 1;
                principal = Principal.in(Ref.slot());
            } else {
                return error.ExpectedEntityOrSlot;
            }
        }
        // '==' (Entity | '?principal')
        else if (matches(tokens, i, .eq)) {
            i = i + 1;
            if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                principal = Principal.eq(
                    Ref.id(entity.entity),
                );
            } else if (matches(tokens, i, .@"?principal")) {
                i = i + 1;
                principal = Principal.eq(Ref.slot());
            } else {
                return error.ExpectedEntity;
            }
            // 'in' ('[' EntList ']' | Entity)
        }

        if (!matches(tokens, i, .comma)) {
            return error.ExpectedComma;
        }
        i = i + 1;

        // Action ::= 'action' [( '==' Entity | 'in' ('[' EntList ']' | Entity) )]
        if (!matches(tokens, i, .action)) {
            return error.ExpectedAction;
        }
        i = i + 1;

        var action = Action.any();

        //  '==' Entity
        if (matches(tokens, i, .eq)) {
            i = i + 1;
            if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                action = Action.eq(
                    Ref.id(entity.entity),
                );
            } else {
                return error.ExpectedEntity;
            }
        }
        // 'in' ('[' EntList ']' | Entity)
        else if (matches(tokens, i, .in)) {
            i = i + 1;
            // '[' EntList ']'
            if (matches(tokens, i, .list_open)) {
                i = i + 1;
                if (try parseEntityList(allocator, tokens, i)) |list| {
                    i = list.nextIndex;
                    // _ = list; // autofix
                }
                if (!matches(tokens, i, .list_close)) {
                    return error.ExpectedListClose;
                }
                i = i + 1;
            } else if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                action = Action.in(
                    Ref.id(entity.entity),
                );
            }
        }

        if (!matches(tokens, i, .comma)) {
            return error.ExpectedComma;
        }
        i = i + 1;

        // Resource ::= 'resource' [(['is' PATH] ['in' (Entity | '?resource')]) | ('==' (Entity | '?resource'))]

        if (!matches(tokens, i, .resource)) {
            return error.ExpectedResource;
        }
        i = i + 1;

        var resource = Resource.any();

        // '==' (Entity | '?resource')
        if (matches(tokens, i, .eq)) {
            i = i + 1;
            if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                resource = Resource.eq(Ref.id(entity.entity));
            } else if (matches(tokens, i, .@"?resource")) {
                i = i + 1;
                resource = Resource.eq(Ref.slot());
            } else {
                return error.ExpectedEntityOrSlot;
            }
            // 'in' (Entity | '?resource')
        } else if (matches(tokens, i, .in)) {
            i = i + 1;
            if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                resource = Resource.in(
                    Ref.id(
                        entity.entity,
                    ),
                );
            } else if (matches(tokens, i, .@"?resource")) {
                i = i + 1;
                resource = Resource.in(Ref.slot());
            } else {
                return error.ExpectedEntityOrSlot;
            }
        }

        if (!matches(tokens, i, .right_paren)) {
            return error.ExpectedCloseParen;
        }
        i = i + 1;

        // Condition ::= ('when' | 'unless') '{' Expr '}'

        if (!matches(tokens, i, .semicolon)) {
            return error.ExpectedSemiColon;
        }
        i = i + 1;

        try policies.append(.{
            .effect = if (forbid) .forbid else .permit,
            .scope = .{
                .principal = principal,
                .action = action,
                .resource = resource,
            },
        });
    }
    return .{ .allocator = allocator, .policies = try policies.toOwnedSlice() };
}

// Entity ::= Path '::' STR
fn parseEntity(tokens: []Token, index: usize) !?struct { nextIndex: usize, entity: EntityUID } {
    var i = index;
    // Path ::= IDENT {'::' IDENT}
    if (matches(tokens, i, .ident)) {
        i = i + 1;
        if (!matches(tokens, i, .path_separator)) {
            return error.ExpectedPathSeparator;
        }
        i = i + 1;
        // STR ::= Fully-escaped Unicode surrounded by '"'s
        if (!matches(tokens, i, .string)) {
            return error.ExpectedEntityId;
        }
        i = i + 1;
        return .{
            .nextIndex = i,
            .entity = EntityUID.init(tokens[i - 3].value(), tokens[i - 1].value()),
        };
    }
    return null;
}

// EntList ::= Entity {',' Entity}
fn parseEntityList(
    allocator: std.mem.Allocator,
    tokens: []Token,
    index: usize,
) !?struct {
    nextIndex: usize,
    entities: []const EntityUID,
} {
    var i: usize = index;
    var list = std.ArrayList(EntityUID).init(allocator);
    defer list.deinit();
    while (try parseEntity(tokens, i)) |ent| {
        i = ent.nextIndex;
        try list.append(ent.entity);
        if (!matches(tokens, i, .comma)) {
            break;
        }
        i = i + 1;
    }
    if (list.items.len > 0) {
        return .{ .nextIndex = i, .entities = try list.toOwnedSlice() };
    }
    return null;
}

fn matches(tokens: []Token, index: usize, kind: Token.Kind) bool {
    return if (index >= tokens.len) false else tokens[index].kind == kind;
}

test parsePolcies {
    const allocator = std.testing.allocator;
    var policySet = try parsePolcies(
        allocator,
        \\permit(
        \\principal == ?principal,
        \\action,
        \\resource in asdf::"1234"
        \\);
        ,
    );
    defer policySet.deinit();
    std.debug.print("parse {any}\n", .{policySet.policies});
}
