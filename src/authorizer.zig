const std = @import("std");
const PolicySet = @import("root.zig").PolicySet;
const Policy = @import("types.zig").Policy;
const Context = @import("root.zig").Context;
const Schema = @import("root.zig").Schema;
const Entities = @import("root.zig").Entities;
const Entity = @import("types.zig").Entity;
const EntityUID = @import("root.zig").EntityUID;
const Expr = @import("types.zig").Expr;
const SlotEnv = @import("types.zig").SlotEnv;
const CendarType = @import("types.zig").CedarType;

/// Represents an evalution outcome which is either a value or residual expression
pub const PartialValue = union(enum) {
    /// a successfully evaluated value
    value: Value,
    /// an incomplete result an evaluation
    residual: Expr,

    /// declares a resolved value
    fn value(v: Value) @This() {
        return .{ .value = v };
    }

    /// declares an unresolved or partially evaluated expression
    fn residual(e: Expr) @This() {
        return .{ .residual = e };
    }
};

/// represents a resolved value from an expression evaluation
pub const Value = union(enum) {
    pub const Set = struct {
        elems: []const Value,
        // todo: "fast" literal set optimization
    };
    literal: Expr.Literal,
    set: Set,
    record: CendarType.Record,
    // todo ext

    fn literal(v: Expr.Literal) @This() {
        return .{ .literal = v };
    }

    fn set(v: Set) @This() {
        return .{ .set = v };
    }

    fn record(v: CendarType.Record) @This() {
        return .{ .record = v };
    }

    /// returns a bool value if this is a literal bool
    /// otherwise return an EvalError
    fn asBool(self: @This()) !bool {
        return switch (self) {
            .literal => |l| switch (l) {
                .bool => |v| v,
                else => error.EvalError,
            },
            else => error.EvalError,
        };
    }

    /// returns an i64 value if this is a literal i64
    /// otherwise return an EvalError
    fn asLong(self: @This()) !i64 {
        return switch (self) {
            .literal => |l| switch (l) {
                .long => |v| v,
                else => error.EvalError,
            },
            else => error.EvalError,
        };
    }

    /// returns an EntityUID value if this is a literal EntityUID
    /// otherwise return an EvalError
    fn asEntity(self: @This()) !EntityUID {
        return switch (self) {
            .literal => |l| switch (l) {
                .entity => |v| v,
                else => error.EvalError,
            },
            else => error.EvalError,
        };
    }

    // std.meta.eq is shallow and auto hashing does not support  net.Address
    // https://github.com/ziglang/zig/issues/19003
    fn eql(self: @This(), other: @This()) bool {
        return switch (self) {
            .literal => |v| switch (other) {
                .literal => |vv| v.eql(vv),
                else => false,
            },
            else => false,
        };
    }

    fn toExpr(self: @This(), _: std.mem.Allocator) !Expr {
        return switch (self) {
            .literal => |v| Expr.literal(v),
            .set => return error.TODO,
            .record => return error.TODO,
        };
    }
};

test "Value.asBool" {
    // only Expr.Literal boolean values are valid
    try std.testing.expectError(error.EvalError, Value.literal(Expr.Literal.entity(EntityUID.init("User", "alice"))).asBool());
    try std.testing.expect(try Value.literal(Expr.Literal.boolean(true)).asBool());
}

test "Value.asLong" {
    // only Expr.Literal long values are valid
    try std.testing.expectError(error.EvalError, Value.literal(Expr.Literal.entity(EntityUID.init("User", "alice"))).asLong());
    try std.testing.expectEqual(1, try Value.literal(Expr.Literal.long(1)).asLong());
}

test "Value.asEntity" {
    // only Expr.Literal entity values are valid
    try std.testing.expectError(error.EvalError, Value.literal(Expr.Literal.boolean(true)).asEntity());
    try std.testing.expect(
        std.meta.eql(
            EntityUID.init("User", "alice"),
            (try Value.literal(Expr.Literal.entity(EntityUID.init("User", "alice"))).asEntity()),
        ),
    );
}

test "Value.eql" {
    for ([_]struct { l: Value, r: Value, expect: bool }{
        .{ .l = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "bar"))), .r = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "bar"))), .expect = true },
        .{ .l = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "bar"))), .r = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "baz"))), .expect = false },
    }) |case| {
        const eq = case.l.eql(case.r);
        std.testing.expect(if (case.expect) eq else !eq) catch |err| {
            std.debug.print(
                "expected {any} when comparing {any} and {any}",
                .{ case.expect, case.l, case.r },
            );
            return err;
        };
    }
}

/// information intended for responding to "why?" questions
pub const Diagnostics = struct {
    /// policy ids of policies that contributed to the decision
    reason: []const []const u8 = &.{},
    // errors
};

/// The primary interface for answering authorization questions
pub const Authorizer = struct {
    pub const Response = struct {
        /// outcome of authorization query
        pub const Decision = enum {
            allow,
            deny,
        };
        /// the authorization decision, defaults to deny
        decision: Decision = .deny,
        diagnostics: Diagnostics = .{},
    };

    /// per-request authorization query inputs
    pub const Request = struct {
        principal: EntityUID,
        action: EntityUID,
        resource: EntityUID,
        context: Context = .{},
        schema: ?Schema = null,
    };

    pub fn init() @This() {
        return .{};
    }

    /// Returns a Response containing information about the outcome of for a given
    /// authorization request
    pub fn isAuthorized(
        _: @This(),
        request: Request,
        policySet: PolicySet,
        entities: Entities,
    ) Response {
        // see https://github.com/cedar-policy/cedar/blob/fdcd70375c838be589e586392c0f95c623b9a78d/cedar-policy-core/src/authorizer.rs#L93

        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var eval = Evaluator.init(allocator, request, entities) catch |e| {
            std.debug.print("eval error: {any}\n", .{e});
            return .{ .decision = .deny };
        };
        defer eval.deinit();
        for (policySet.policies) |p| {
            // todo: aggregate answers to from all policies before
            // coming to a decision
            const result = eval.evaluate(p) catch |e| {
                // todo communicate error through response type
                std.debug.print("eval error: {any}\n", .{e});
                return .{ .decision = .deny };
            };
            return .{ .decision = if (result) .allow else .deny };
        }
        // default to deny
        return .{ .decision = .deny };
    }
};

const PartialResponse = struct {};

// internal implementation
const Evaluator = struct {
    arena: *std.heap.ArenaAllocator,
    request: Authorizer.Request,
    entities: Entities,

    fn init(allocator: std.mem.Allocator, request: Authorizer.Request, entities: Entities) !@This() {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        return .{ .arena = arena, .request = request, .entities = entities };
    }

    fn deinit(self: *@This()) void {
        const alloc = self.arena.child_allocator;
        self.arena.deinit();
        alloc.destroy(self.arena);
    }

    /// evaluates an expression, returns true if this results an a literal `true` result
    fn evaluate(self: @This(), policy: Policy) !bool {
        // todo: pass policy.env
        return (try self.interpret(try policy.condition(self.arena.allocator()))).asBool();
    }

    /// translates a partial interpreter result to an error
    /// and returns the value of resolved expressions
    fn interpret(self: @This(), expr: Expr) !Value {
        return switch (try self.partialInterpret(expr)) {
            .value => |v| v,
            .residual => error.EvalError,
        };
    }

    fn evalPrincipal(self: @This()) PartialValue {
        return PartialValue.value(Value.literal(Expr.Literal.entity(self.request.principal)));
    }

    fn evalAction(self: @This()) PartialValue {
        return PartialValue.value(Value.literal(Expr.Literal.entity(self.request.action)));
    }

    fn evalResource(self: @This()) PartialValue {
        return PartialValue.value(Value.literal(Expr.Literal.entity(self.request.resource)));
    }

    fn partialInterpret(self: @This(), expr: Expr) !PartialValue {
        // https://github.com/cedar-policy/cedar/blob/67131d64bb80cfa9cc861e999ede365d1bcbb26a/cedar-policy-core/src/evaluator.rs#L279
        return switch (expr) {
            .literal => |v| PartialValue.value(Value.literal(v)),
            .set => |v| blk: {
                var partials = try std.ArrayList(PartialValue).initCapacity(self.arena.allocator(), v.len);
                defer partials.deinit();
                for (v) |elem| {
                    partials.appendAssumeCapacity(try self.partialInterpret(elem.*));
                }
                const splitPartials = try self.split(try partials.toOwnedSlice());

                break :blk switch (splitPartials) {
                    .values => |vv| PartialValue.value(Value.set(.{ .elems = vv })),
                    .residuals => |vv| PartialValue.residual(Expr.set(vv)),
                };
            },
            .variable => |v| switch (v) {
                .principal => self.evalPrincipal(),
                .action => self.evalAction(),
                .resource => self.evalResource(),
                .context => return error.TODO,
            },
            .pattern => |v| {
                std.debug.print("pattern {any}\n", .{v});
                return error.TODO;
            },
            .slot => |v| {
                std.debug.print("slot {any}\n", .{v});
                return error.TODO;
            },
            .ite => |v| switch (try self.partialInterpret(v.@"if".*)) {
                .value => |vv| if (try vv.asBool()) try self.partialInterpret(v.then.*) else try self.partialInterpret(v.@"else".*),
                .residual => |vv| PartialValue.residual(Expr.ite(try vv.heapify(self.arena.allocator()), try v.then.*.heapify(self.arena.allocator()), try v.@"else".*.heapify(self.arena.allocator()))),
            },
            .@"and" => |v| switch (try self.partialInterpret(v.left.*)) {
                .value => |ll| if (try ll.asBool())
                    switch (try self.partialInterpret(v.right.*)) {
                        .value => |rr| PartialValue.value(Value.literal(Expr.Literal.boolean(try rr.asBool()))),
                        .residual => |rr| PartialValue.residual(
                            Expr.@"and"(
                                try Expr.literal(Expr.Literal.boolean(true)).heapify(self.arena.allocator()),
                                try rr.heapify(self.arena.allocator()),
                            ),
                        ),
                    }
                else
                    PartialValue.value(Value.literal(Expr.Literal.boolean(false))), // doesn't matter what v.right is, short circut here

                .residual => |ll| PartialValue.residual(ll),
            },
            .@"or" => |v| blk: {
                std.debug.print("or {any}\n", .{v});
                break :blk switch (try self.partialInterpret(v.left.*)) {
                    .value => |ll| if (try ll.asBool()) PartialValue.value(Value.literal(Expr.Literal.boolean(true))) // doesn't matter what v.right is, short circut here
                    else switch (try self.partialInterpret(v.right.*)) {
                        .value => |rr| PartialValue.value(Value.literal(Expr.Literal.boolean(try rr.asBool()))),
                        .residual => |rr| PartialValue.residual(Expr.@"or"(Expr.literal(Expr.Literal.boolean(false)), rr)),
                    },
                    .residual => |ll| PartialValue.residual(Expr.@"or"(ll, v.right.*)),
                };
            },
            .unary => |v| switch (try self.partialInterpret(v.arg.*)) {
                .value => |vv| switch (v.op) {
                    .not => PartialValue.value(Value.literal(Expr.Literal.boolean(try vv.asBool()))),
                    .neg => blk: {
                        if (std.math.negate(try vv.asLong())) |neg| {
                            break :blk PartialValue.value(Value.literal(Expr.Literal.long(neg)));
                        } else |err| {
                            std.debug.print("error negating long {any}: {any}", .{ v, err });
                            return error.EvalError;
                        }
                    },
                },
                .residual => |vv| PartialValue.residual(Expr.unary(v.op, try vv.heapify(self.arena.allocator()))),
            },
            .binary => |v| blk: {
                const a = try self.partialInterpret(v.arg1.*);
                const b = try self.partialInterpret(v.arg2.*);
                const op = v.op;
                const va, const vb = switch (a) {
                    .value => |aa| switch (b) {
                        .value => |bb| .{ aa, bb },
                        .residual => return error.TODO,
                    },
                    .residual => |aa| switch (b) {
                        .value => return error.TODO,
                        .residual => |bb| {
                            std.debug.print("returning residual for binary op {}\n", .{op});
                            return PartialValue.residual(Expr.binary(op, try aa.heapify(self.arena.allocator()), try bb.heapify(self.arena.allocator())));
                        },
                    },
                };
                switch (v.op) {
                    .eq => break :blk PartialValue.value(
                        Value.literal(
                            Expr.Literal.boolean(va.eql(vb)),
                        ),
                    ),
                    .lt, .lte, .add, .sub, .mul => {
                        const la = try va.asLong();
                        const lb = try vb.asLong();
                        break :blk PartialValue.value(
                            Value.literal(switch (v.op) {
                                .lt => Expr.Literal.boolean(la == lb),
                                .lte => Expr.Literal.boolean(la <= lb),
                                .add => Expr.Literal.long(try std.math.add(i64, la, lb)),
                                .sub => Expr.Literal.long(try std.math.sub(i64, la, lb)),
                                .mul => Expr.Literal.long(try std.math.mul(i64, la, lb)),
                                else => unreachable, // expect cases are covered above
                            }),
                        );
                    },
                    .in => {
                        const id = va.asEntity() catch |err| {
                            std.debug.print("expected arg1 to be an entity but instead it was was a {any}", .{va});
                            return err;
                        };
                        break :blk switch (self.entities.entity(id)) {
                            .data => |e| self.evalIn(id, e, vb),
                            .none => self.evalIn(id, null, vb),
                            .residual => return error.TODO, //|v| PartialValue.residual(Expr.in(try v.heapify(allocator), v)),
                        };
                    },
                    .contains => {},
                    .contains_all => {},
                    .contains_any => {},
                }
                std.debug.print("returning fall through for uninplemented binary op {}\n", .{op});
                return error.TODO;
            },
            .is => |v| switch (try self.partialInterpret(v.expr.*)) {
                .value => |vv| PartialValue.value(
                    Value.literal(
                        Expr.Literal.boolean(std.mem.eql(u8, (try vv.asEntity()).type, v.type)),
                    ),
                ),
                .residual => |vv| PartialValue.residual(
                    Expr.isEntityType(try vv.heapify(self.arena.allocator()), v.type),
                ),
            },
            .unknown => PartialValue.residual(expr), // the unknown case
        };
    }

    /// resolves to partial value true, if arg2 is a literal entity value that matches uid or entity is a decendant of it
    fn evalIn(_: @This(), uid: EntityUID, entity: ?Entity, arg2: Value) !PartialValue {
        return switch (arg2) {
            .literal => |v| switch (v) {
                .entity => |e| PartialValue.value(
                    Value.literal(
                        Expr.Literal.boolean(
                            e.eql(uid) or if (entity) |ent| ent.isDecendantOf(e) else false,
                        ),
                    ),
                ),
                else => return error.EvalError, // expect entity literal type
            },
            .set => |v| blk: {
                for (v.elems) |ct| {
                    if (ct.asEntity()) |e| {
                        if (e.eql(uid)) {
                            break :blk PartialValue.value(Value.literal(Expr.Literal.boolean(true)));
                        }
                        if (entity) |ent| {
                            if (ent.isDecendantOf(e)) {
                                break :blk PartialValue.value(Value.literal(Expr.Literal.boolean(true)));
                            }
                        }
                    } else |err| {
                        std.debug.print("{}", .{err});
                    }
                }
                break :blk PartialValue.value(Value.literal(Expr.Literal.boolean(false)));
            },
            else => return error.EvalError, // expect set or entity literal types
        };
    }

    const Split = union(enum) {
        values: []const Value,
        residuals: []*const Expr,
    };

    fn split(self: @This(), partials: []const PartialValue) !Split {
        var values = std.ArrayList(Value).init(self.arena.allocator());
        var residuals = std.ArrayList(*const Expr).init(self.arena.allocator());
        for (partials) |p| {
            switch (p) {
                .value => |v| if (residuals.items.len == 0)
                    try values.append(v)
                else
                    try residuals.append(try (try v.toExpr(self.arena.allocator())).heapify(self.arena.allocator())),
                .residual => |v| try residuals.append(try v.heapify(self.arena.allocator())),
            }
        }
        if (residuals.items.len == 0) {
            return .{ .values = try values.toOwnedSlice() };
        } else {
            for (values.items) |v| try residuals.append(try (try v.toExpr(self.arena.allocator())).heapify(self.arena.allocator()));
            return .{ .residuals = try residuals.toOwnedSlice() };
        }
    }
};

test "Evaluator.evaluate" {
    const allocator = std.testing.allocator;
    var entities = try Entities.fromJson(
        allocator,
        \\[{
        \\  "uid": { "type": "User", "id": "a" },
        \\  "attrs": {},
        \\  "parents": [{
        \\     "type":"Role",
        \\     "id": "admin"
        \\  }]
        \\}, {
        \\  "uid": { "type": "Role", "id": "admin" },
        \\  "attrs": {},
        \\  "parents": []
        \\}]
        ,
    );
    defer entities.deinit();

    var eval = try Evaluator.init(
        allocator,
        .{
            .principal = EntityUID.init("User", "a"),
            .action = EntityUID.init("Action", "b"),
            .resource = EntityUID.init("Resource", "c"),
        },
        entities,
    );
    defer eval.deinit();

    var policySet = try @import("root.zig").parse(allocator,
        \\permit(
        \\    principal is User in Role::"admin",
        \\    action in [Action::"b", Action::"d"],
        \\    resource == Resource::"c"
        \\);
    );
    defer policySet.deinit();

    try std.testing.expect(eval.evaluate(policySet.policies[0]) catch |err| {
        std.debug.print("expected true but error was returned {any}\n", .{err});
        return err;
    });
}
