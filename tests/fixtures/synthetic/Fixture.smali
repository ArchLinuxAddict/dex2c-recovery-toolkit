.class public Ldex2c_recover/Fixture;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static answer()I
    .registers 1
    const/16 v0, 0x2a
    return v0
.end method

.method public static add(II)I
    .registers 3
    add-int v0, p0, p1
    return v0
.end method
