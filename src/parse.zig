// see also syntax-policy.html
// parser inspired  by https://notes.eatonphil.com/zigrocks-sql.html
const std = @import("std");
const types = @import("types.zig");

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
        left_paren, // (
        right_paren, // )
        semicolon, // ;
        comma, // ,
        path_separator, // ::
        list_open, // [
        list_close, // ]
        left_brace, // {
        right_brace, // }
        at, // @

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
    .{ .name = "@", .kind = .at },
    .{ .name = "[", .kind = .list_open },
    .{ .name = "]", .kind = .list_close },
    .{ .name = "(", .kind = .left_paren },
    .{ .name = ")", .kind = .right_paren },
    .{ .name = "{", .kind = .left_brace },
    .{ .name = "}", .kind = .right_brace },
    .{ .name = ",", .kind = .comma },
    .{ .name = ";", .kind = .semicolon },
};

/// https://notes.eatonphil.com/zigrocks-sql.html
fn lex(source: []const u8, tokens: *std.ArrayList(Token)) !void {
    var i: usize = 0;
    while (i < source.len) {
        i = try skip(source, i);
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

        std.debug.print("invalid token found at position {d} '{s}'\n", .{ i, [_]u8{source[i]} });
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
fn skip(source: []const u8, index: usize) !usize {
    var next = index;
    // skip over whitespace and new lines
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

    // skip over comment
    // COMMENT ::= '//' ~NEWLINE* NEWLINE
    while (source[next] == '/') {
        if (next + 1 != source.len and source[next + 1] == '/') {
            next = next + 2;
            while (source[next] != '\n' and next != source.len) {
                next = next + 1;
            }
            next = next + 1;
        } else {
            return error.InvalidComment;
        }
    }

    return next;
}

// parsing

/// parse a set of policies from a string
pub fn parsePolcies(allocator: std.mem.Allocator, source: []const u8) !types.PolicySet {
    var tokens = std.ArrayList(Token).init(allocator);
    defer tokens.deinit();
    try lex(source, &tokens);
    const slice = try tokens.toOwnedSlice();
    defer allocator.free(slice);
    return try parse(allocator, slice);
}

fn parse(allocator: std.mem.Allocator, tokens: []Token) !types.PolicySet {
    var policySet = types.PolicySet{
        .arena = try allocator.create(std.heap.ArenaAllocator),
        .policies = undefined,
    };
    policySet.arena.* = std.heap.ArenaAllocator.init(allocator);

    var policies = std.ArrayList(types.Policy).init(policySet.arena.allocator());
    defer policies.deinit();
    var i: usize = 0;

    while (i < tokens.len) {
        // Policy ::= {Annotation} Effect '(' Scope ')' {Conditions} ';'

        var annotations = std.ArrayList(types.Annotation).init(policySet.arena.allocator());
        defer annotations.deinit();

        while (try parseAnnotation(tokens, i)) |annot| {
            i = annot.nextIndex;
            try annotations.append(annot.annotation);
        }

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

        var principal = types.Principal.any();

        if (matches(tokens, i, .in)) {
            i = i + 1;
            if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                principal = types.Principal.in(
                    types.Ref.id(entity.entity),
                );
            } else if (matches(tokens, i, .@"?principal")) {
                i = i + 1;
                principal = types.Principal.in(types.Ref.slot());
            } else {
                return error.ExpectedEntityOrSlot;
            }
        }
        // '==' (Entity | '?principal')
        else if (matches(tokens, i, .eq)) {
            i = i + 1;
            if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                principal = types.Principal.eq(
                    types.Ref.id(entity.entity),
                );
            } else if (matches(tokens, i, .@"?principal")) {
                i = i + 1;
                principal = types.Principal.eq(types.Ref.slot());
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

        var action = types.Action.any();

        //  '==' Entity
        if (matches(tokens, i, .eq)) {
            i = i + 1;
            if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                action = types.Action.eq(
                    types.Ref.id(entity.entity),
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
                if (try parseEntityList(policySet.arena.allocator(), tokens, i)) |list| {
                    i = list.nextIndex;
                    // _ = list; // autofix
                }
                if (!matches(tokens, i, .list_close)) {
                    return error.ExpectedListClose;
                }
                i = i + 1;
            } else if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                action = types.Action.in(
                    types.Ref.id(entity.entity),
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

        var resource = types.Resource.any();

        // '==' (Entity | '?resource')
        if (matches(tokens, i, .eq)) {
            i = i + 1;
            if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                resource = types.Resource.eq(types.Ref.id(entity.entity));
            } else if (matches(tokens, i, .@"?resource")) {
                i = i + 1;
                resource = types.Resource.eq(types.Ref.slot());
            } else {
                return error.ExpectedEntityOrSlot;
            }
            // 'in' (Entity | '?resource')
        } else if (matches(tokens, i, .in)) {
            i = i + 1;
            if (try parseEntity(tokens, i)) |entity| {
                i = entity.nextIndex;
                resource = types.Resource.in(
                    types.Ref.id(
                        entity.entity,
                    ),
                );
            } else if (matches(tokens, i, .@"?resource")) {
                i = i + 1;
                resource = types.Resource.in(types.Ref.slot());
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
            .annotations = try annotations.toOwnedSlice(),
            .effect = if (forbid) .forbid else .permit,
            .scope = .{
                .principal = principal,
                .action = action,
                .resource = resource,
            },
        });
    }

    policySet.policies = try policies.toOwnedSlice();

    return policySet;
}

// Entity ::= Path '::' STR
fn parseEntity(tokens: []Token, index: usize) !?struct { nextIndex: usize, entity: types.EntityUID } {
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
            .entity = types.EntityUID.init(tokens[i - 3].value(), tokens[i - 1].value()),
        };
    }
    return null;
}

// Annotation ::= '@'IDENT'('STR')'
fn parseAnnotation(tokens: []Token, index: usize) !?struct { nextIndex: usize, annotation: types.Annotation } {
    var i = index;
    if (matches(tokens, i, .at)) {
        i = i + 1;
        if (!matches(tokens, i, .ident)) {
            return error.ExpectedOpenParen;
        }
        const name = tokens[i].value();
        i = i + 1;

        if (!matches(tokens, i, .left_paren)) {
            return error.ExpectedOpenParen;
        }
        i = i + 1;

        if (!matches(tokens, i, .string)) {
            return error.ExpectedString;
        }
        const value = tokens[i].value();
        i = i + 1;

        if (!matches(tokens, i, .right_paren)) {
            return error.ExpectedCloseParen;
        }
        i = i + 1;

        return .{
            .nextIndex = i,
            .annotation = types.Annotation.init(name, value),
        };
    }
    return null;
}

// Condition ::= ('when' | 'unless') '{' Expr '}'
fn parseCondition(tokens: []Token, index: usize) !?struct { nextIndex: usize, when: bool, annotation: types.Expr } {
    var i = index;
    const when = matches(tokens, index, .when);
    const unless = matches(tokens, index, .unless);
    if (when or unless) {
        i = i + 1;
        if (!matches(tokens, i, .left_brace)) {
            return error.ExpectedLeftBrace;
        }
        i = i + 1;

        if (try parseExpr(tokens, i)) |expr| {
            i = expr.nextIndex;
        } else {
            return error.ExpectedExpr;
        }

        if (!matches(tokens, i, .right_brace)) {
            return error.ExpectedRightBrace;
        }
        i = i + 1;
    }
    return null;
}

fn parseExpr(tokens: []Token, index: usize) !?struct { nextIndex: usize, expr: types.Expr } {
    _ = tokens; // autofix
    _ = index; // autofix
    return null;
}

// EntList ::= Entity {',' Entity}
fn parseEntityList(
    allocator: std.mem.Allocator,
    tokens: []Token,
    index: usize,
) !?struct {
    nextIndex: usize,
    entities: []const types.EntityUID,
} {
    var i: usize = index;
    var list = std.ArrayList(types.EntityUID).init(allocator);
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
        \\// a multi line
        \\// comment
        \\@annot(
        \\ "value"
        \\)
        \\permit(
        \\  principal == ?principal,
        \\  action,
        \\  resource in asdf::"1234"
        \\);
        ,
    );
    defer policySet.deinit();
    for (policySet.policies) |p| std.debug.print("{s}\n", .{p});
}
