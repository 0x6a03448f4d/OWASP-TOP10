# API03: Broken Object Property Level Authorization - Examples

## Table of Contents
- [Vulnerable vs Secure Patterns](#vulnerable-vs-secure-patterns)
- [Flask Examples](#flask-examples)
- [FastAPI Examples](#fastapi-examples)
- [Express.js Examples](#expressjs-examples)
- [Django Examples](#django-examples)
- [Complete Application Examples](#complete-application-examples)

## Vulnerable vs Secure Patterns

### Pattern 1: User Profile Endpoint

#### ❌ VULNERABLE: Direct Model Serialization

```python
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    password_hash = db.Column(db.String(255))
    api_key = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)
    salary = db.Column(db.Integer)
    ssn = db.Column(db.String(11))

@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    # ❌ VULNERABILITY: Exposes ALL fields including sensitive data
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'password_hash': user.password_hash,  # ❌ EXPOSED!
        'api_key': user.api_key,              # ❌ EXPOSED!
        'is_admin': user.is_admin,            # ❌ EXPOSED!
        'salary': user.salary,                # ❌ EXPOSED!
        'ssn': user.ssn                       # ❌ EXPOSED!
    })
```

**Why it's vulnerable:**
- Exposes password hash (even hashed passwords can be cracked)
- Leaks API keys allowing impersonation
- Reveals admin status (aids privilege escalation)
- Exposes salary and SSN (privacy violations, compliance issues)

#### ✅ SECURE: DTO with Field Filtering

```python
from flask import Flask, jsonify
from marshmallow import Schema, fields

class User(db.Model):
    # ... same model definition ...
    pass

class UserPublicSchema(Schema):
    """Public profile - safe for all authenticated users"""
    id = fields.Int(dump_only=True)
    username = fields.Str()
    email = fields.Email()
    # ✅ password_hash NOT included
    # ✅ api_key NOT included
    # ✅ is_admin NOT included
    # ✅ salary NOT included
    # ✅ ssn NOT included

class UserPrivateSchema(UserPublicSchema):
    """User's own profile - includes private info"""
    phone = fields.Str()
    created_at = fields.DateTime()

class UserAdminSchema(UserPrivateSchema):
    """Admin view - includes admin-only fields"""
    is_admin = fields.Bool()
    last_login_ip = fields.Str()
    # ✅ password_hash STILL not included
    # ✅ ssn STILL not included (separate endpoint)

@app.route('/api/users/<int:user_id>')
@require_auth
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # ✅ Choose schema based on relationship and role
    if current_user.is_admin:
        schema = UserAdminSchema()
    elif current_user.id == user_id:
        schema = UserPrivateSchema()
    else:
        schema = UserPublicSchema()
    
    return jsonify(schema.dump(user))
```

**Why it's secure:**
- Sensitive fields completely excluded from serialization
- Different schemas for different access levels
- Role-based field filtering
- Explicit field allowlisting

### Pattern 2: User Profile Update

#### ❌ VULNERABLE: Mass Assignment

```python
@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.json
    
    # ❌ VULNERABILITY: Accepts ALL fields from request
    for key, value in data.items():
        if hasattr(user, key):
            setattr(user, key, value)
    
    db.session.commit()
    return jsonify({'message': 'Updated'})

# Attacker sends:
# PUT /api/users/123
# {
#   "username": "hacker",
#   "is_admin": true,      ← ACCEPTED!
#   "salary": 999999,      ← ACCEPTED!
#   "balance": 1000000     ← ACCEPTED!
# }
```

**Why it's vulnerable:**
- No field allowlist - accepts any property
- Users can escalate privileges (is_admin: true)
- Financial fraud possible (balance, salary modification)
- No distinction between user-updatable and admin-only fields

#### ✅ SECURE: Allowlist with Validation

```python
from marshmallow import Schema, fields, validates, ValidationError

class UserUpdateSchema(Schema):
    """Only these fields can be updated by users"""
    username = fields.Str(validate=Length(min=3, max=50))
    email = fields.Email()
    phone = fields.Str()
    # ✅ is_admin NOT in schema = cannot be updated
    # ✅ salary NOT in schema = cannot be updated
    # ✅ balance NOT in schema = cannot be updated

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    # ✅ Authorization check
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    # ✅ Validate and filter input
    schema = UserUpdateSchema()
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400
    
    # ✅ Only update allowed fields
    for key, value in data.items():
        setattr(user, key, value)
    
    db.session.commit()
    
    # ✅ Return filtered response
    return jsonify(UserPublicSchema().dump(user))

# Attacker sends:
# PUT /api/users/123
# {
#   "username": "updated",
#   "is_admin": true        ← IGNORED by schema!
# }
# Result: Only username updated, is_admin remains false
```

**Why it's secure:**
- Explicit allowlist of updatable fields
- Schema validation rejects unknown fields
- Authorization check ensures user owns resource
- Separate response schema for output filtering

## Flask Examples

### Example 1: E-commerce Product API

#### ❌ VULNERABLE Implementation

```python
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2))
    cost = db.Column(db.Numeric(10, 2))  # Wholesale cost
    stock = db.Column(db.Integer)
    is_featured = db.Column(db.Boolean)
    internal_notes = db.Column(db.Text)  # Private notes

@app.route('/api/products/<int:product_id>')
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    # ❌ Exposes everything
    return jsonify({
        'id': product.id,
        'name': product.name,
        'description': product.description,
        'price': float(product.price),
        'cost': float(product.cost),              # ❌ Business secret!
        'stock': product.stock,
        'is_featured': product.is_featured,
        'internal_notes': product.internal_notes  # ❌ Internal info!
    })

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@require_auth
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    data = request.json
    
    # ❌ User can modify price!
    if 'price' in data:
        product.price = data['price']  # ❌ Price manipulation!
    if 'stock' in data:
        product.stock = data['stock']  # ❌ Stock manipulation!
    if 'is_featured' in data:
        product.is_featured = data['is_featured']  # ❌ Unauthorized promotion!
    
    db.session.commit()
    return jsonify({'message': 'Updated'})
```

#### ✅ SECURE Implementation

```python
from marshmallow import Schema, fields, validate

class ProductPublicSchema(Schema):
    """Public product view - safe for all users"""
    id = fields.Int(dump_only=True)
    name = fields.Str()
    description = fields.Str()
    price = fields.Decimal(as_string=True)
    stock = fields.Int()
    is_featured = fields.Bool()
    # ✅ cost NOT included (business secret)
    # ✅ internal_notes NOT included

class ProductAdminSchema(ProductPublicSchema):
    """Admin view - includes business data"""
    cost = fields.Decimal(as_string=True)
    internal_notes = fields.Str()

class ProductUpdateSchema(Schema):
    """Regular users can only update description"""
    description = fields.Str(validate=validate.Length(max=1000))
    # ✅ price NOT updatable by users
    # ✅ stock NOT updatable by users
    # ✅ is_featured NOT updatable by users

class ProductAdminUpdateSchema(Schema):
    """Admins can update all business fields"""
    name = fields.Str()
    description = fields.Str()
    price = fields.Decimal()
    cost = fields.Decimal()
    stock = fields.Int()
    is_featured = fields.Bool()

@app.route('/api/products/<int:product_id>')
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # ✅ Different schema for admins
    if current_user and current_user.is_admin:
        schema = ProductAdminSchema()
    else:
        schema = ProductPublicSchema()
    
    return jsonify(schema.dump(product))

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@require_auth
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # ✅ Different schema based on role
    if current_user.is_admin:
        schema = ProductAdminUpdateSchema()
    else:
        schema = ProductUpdateSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400
    
    # ✅ Safe to update - only allowed fields present
    for key, value in data.items():
        setattr(product, key, value)
    
    db.session.commit()
    return jsonify(ProductPublicSchema().dump(product))
```

### Example 2: Order Management API

#### ❌ VULNERABLE Implementation

```python
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    items = db.Column(db.JSON)
    total = db.Column(db.Numeric(10, 2))
    status = db.Column(db.String(50))  # pending, paid, shipped
    discount_code = db.Column(db.String(50))
    discount_percent = db.Column(db.Integer)
    is_verified = db.Column(db.Boolean)

@app.route('/api/orders', methods=['POST'])
@require_auth
def create_order():
    data = request.json
    
    # ❌ Accepts all fields from user
    order = Order(
        user_id=current_user.id,
        items=data['items'],
        total=data.get('total', 0),  # ❌ User controls price!
        status=data.get('status', 'pending'),  # ❌ Can set to 'paid'!
        discount_percent=data.get('discount_percent', 0),  # ❌ Arbitrary discount!
        is_verified=data.get('is_verified', False)  # ❌ Can bypass verification!
    )
    
    db.session.add(order)
    db.session.commit()
    return jsonify({'order_id': order.id})
```

#### ✅ SECURE Implementation

```python
from decimal import Decimal

class OrderCreateSchema(Schema):
    """Users can only provide items and discount code"""
    items = fields.List(fields.Dict(), required=True)
    discount_code = fields.Str(required=False)
    # ✅ total calculated server-side
    # ✅ status set server-side
    # ✅ discount_percent validated server-side
    # ✅ is_verified set server-side

class OrderResponseSchema(Schema):
    """What users see in response"""
    id = fields.Int()
    items = fields.List(fields.Dict())
    total = fields.Decimal(as_string=True)
    status = fields.Str()
    discount_percent = fields.Int()
    created_at = fields.DateTime()
    # ✅ is_verified not shown to users

class OrderAdminResponseSchema(OrderResponseSchema):
    """What admins see"""
    is_verified = fields.Bool()
    user_id = fields.Int()

@app.route('/api/orders', methods=['POST'])
@require_auth
def create_order():
    schema = OrderCreateSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400
    
    # ✅ Calculate total server-side
    total = calculate_order_total(data['items'])
    
    # ✅ Validate and apply discount server-side
    discount_percent = 0
    if 'discount_code' in data:
        discount = validate_discount_code(data['discount_code'])
        if discount:
            discount_percent = discount.percent
            total = total * (1 - discount_percent / 100)
    
    # ✅ Server controls all sensitive fields
    order = Order(
        user_id=current_user.id,
        items=data['items'],
        total=total,  # ✅ Server-calculated
        status='pending',  # ✅ Server-set
        discount_percent=discount_percent,  # ✅ Server-validated
        is_verified=False  # ✅ Server-set
    )
    
    db.session.add(order)
    db.session.commit()
    
    return jsonify(OrderResponseSchema().dump(order)), 201
```

## FastAPI Examples

### Example 3: User Management with Pydantic

#### ❌ VULNERABLE Implementation

```python
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

app = FastAPI()

@app.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    # ❌ Returns ORM model directly - exposes ALL fields!
    return user

@app.put("/users/{user_id}")
def update_user(user_id: int, data: dict, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    # ❌ Mass assignment - accepts any field!
    for key, value in data.items():
        setattr(user, key, value)
    db.commit()
    return user
```

#### ✅ SECURE Implementation

```python
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
from datetime import datetime

# Response Models
class UserPublicResponse(BaseModel):
    """Public user profile"""
    id: int
    username: str
    email: EmailStr
    created_at: datetime
    
    class Config:
        from_attributes = True

class UserPrivateResponse(UserPublicResponse):
    """User's own profile"""
    phone: Optional[str] = None
    email_verified: bool

class UserAdminResponse(UserPrivateResponse):
    """Admin view"""
    is_admin: bool
    is_active: bool
    last_login_at: Optional[datetime] = None
    # ✅ password_hash STILL not included

# Input Models
class UserUpdateRequest(BaseModel):
    """User can only update these fields"""
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    
    @validator('username')
    def validate_username(cls, v):
        if v and not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v

class UserAdminUpdateRequest(UserUpdateRequest):
    """Admins can update additional fields"""
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None

# Secure Endpoints
@app.get("/users/{user_id}", response_model=UserPublicResponse)
def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404)
    
    # ✅ Pydantic filters to UserPublicResponse fields only
    return user

@app.get("/users/me", response_model=UserPrivateResponse)
def get_my_profile(current_user: User = Depends(get_current_user)):
    # ✅ Returns more fields for own profile
    return current_user

@app.put("/users/{user_id}", response_model=UserPrivateResponse)
def update_user(
    user_id: int,
    update_data: UserUpdateRequest,  # ✅ Validates and filters input
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=403)
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404)
    
    # ✅ Only update provided fields
    update_dict = update_data.dict(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(user, key, value)
    
    db.commit()
    db.refresh(user)
    return user

@app.put("/admin/users/{user_id}", response_model=UserAdminResponse)
def admin_update_user(
    user_id: int,
    update_data: UserAdminUpdateRequest,  # ✅ Admin can update more fields
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404)
    
    update_dict = update_data.dict(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(user, key, value)
    
    db.commit()
    db.refresh(user)
    return user
```

## Express.js Examples

### Example 4: TypeScript API with DTOs

#### ❌ VULNERABLE Implementation

```typescript
import express from 'express';

const app = express();

// ❌ No type safety, exposes everything
app.get('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user);  // Sends ALL fields!
});

app.put('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    // ❌ Mass assignment
    Object.assign(user, req.body);
    await user.save();
    res.json(user);
});
```

#### ✅ SECURE Implementation

```typescript
import { IsString, IsEmail, IsOptional, Length, IsBoolean } from 'class-validator';
import { Exclude, Expose, plainToClass } from 'class-transformer';

// Response DTOs
export class UserPublicDto {
    @Expose()
    id: number;
    
    @Expose()
    username: string;
    
    @Expose()
    email: string;
    
    @Expose()
    createdAt: Date;
    
    // All other fields excluded by default
}

export class UserPrivateDto extends UserPublicDto {
    @Expose()
    phone: string;
    
    @Expose()
    emailVerified: boolean;
}

export class UserAdminDto extends UserPrivateDto {
    @Expose()
    isAdmin: boolean;
    
    @Expose()
    lastLoginAt: Date;
}

// Input DTOs
export class UserUpdateDto {
    @IsOptional()
    @IsString()
    @Length(3, 50)
    username?: string;
    
    @IsOptional()
    @IsEmail()
    email?: string;
    
    @IsOptional()
    @IsString()
    phone?: string;
    
    // isAdmin, salary, etc. NOT included
}

export class UserAdminUpdateDto extends UserUpdateDto {
    @IsOptional()
    @IsBoolean()
    isActive?: boolean;
    
    @IsOptional()
    @IsBoolean()
    isAdmin?: boolean;
}

// Validation Middleware
async function validateDto(dtoClass: any) {
    return async (req: Request, res: Response, next: NextFunction) => {
        const dto = plainToClass(dtoClass, req.body);
        const errors = await validate(dto);
        
        if (errors.length > 0) {
            return res.status(400).json({
                error: 'Validation failed',
                details: errors
            });
        }
        
        req.body = dto;
        next();
    };
}

// Secure Endpoints
app.get('/api/users/:id', authenticate, async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    // ✅ Choose DTO based on relationship
    let dtoClass = UserPublicDto;
    if (req.user.isAdmin) {
        dtoClass = UserAdminDto;
    } else if (req.user.id === user.id) {
        dtoClass = UserPrivateDto;
    }
    
    // ✅ Transform and filter fields
    const response = plainToClass(dtoClass, user, {
        excludeExtraneousValues: true
    });
    
    res.json(response);
});

app.put('/api/users/:id',
    authenticate,
    validateDto(UserUpdateDto),
    async (req, res) => {
        const userId = parseInt(req.params.id);
        
        // ✅ Authorization check
        if (req.user.id !== userId && !req.user.isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // ✅ Safe update - only DTO fields
        const updateDto = plainToClass(UserUpdateDto, req.body);
        Object.assign(user, updateDto);
        await user.save();
        
        // ✅ Safe response
        const response = plainToClass(UserPrivateDto, user, {
            excludeExtraneousValues: true
        });
        
        res.json(response);
    }
);
```

## Django Examples

### Example 5: Django REST Framework Serializers

#### ❌ VULNERABLE Implementation

```python
from rest_framework import serializers, viewsets
from django.contrib.auth.models import User

# ❌ Exposes ALL fields
class VulnerableUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

# ❌ No field restrictions
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = VulnerableUserSerializer
```

#### ✅ SECURE Implementation

```python
from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

# Read Serializers
class UserPublicSerializer(serializers.ModelSerializer):
    """Public profile"""
    class Meta:
        model = User
        fields = ['id', 'username', 'date_joined']
        read_only_fields = ['id', 'date_joined']

class UserPrivateSerializer(serializers.ModelSerializer):
    """User's own profile"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 
                  'last_name', 'date_joined']
        read_only_fields = ['id', 'date_joined']

class UserAdminSerializer(serializers.ModelSerializer):
    """Admin view"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'is_staff', 
                  'is_active', 'date_joined', 'last_login']
        read_only_fields = ['id', 'date_joined', 'last_login']

# Write Serializers
class UserUpdateSerializer(serializers.ModelSerializer):
    """User can only update these fields"""
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exclude(
            pk=self.instance.pk
        ).exists():
            raise serializers.ValidationError("Email already in use")
        return value

class UserAdminUpdateSerializer(serializers.ModelSerializer):
    """Admins can update additional fields"""
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name',
                  'is_active', 'is_staff']

# Secure ViewSet
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    
    def get_serializer_class(self):
        """Choose serializer based on action and permissions"""
        if self.action in ['create', 'update', 'partial_update']:
            if self.request.user.is_staff:
                return UserAdminUpdateSerializer
            return UserUpdateSerializer
        
        if self.action == 'me':
            return UserPrivateSerializer
        
        if self.request.user.is_staff:
            return UserAdminSerializer
        
        return UserPublicSerializer
    
    def get_queryset(self):
        """Filter queryset based on permissions"""
        if self.request.user.is_staff:
            return User.objects.all()
        return User.objects.filter(is_active=True)
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """User's own profile"""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)
    
    def update(self, request, *args, **kwargs):
        """Override update to add authorization"""
        instance = self.get_object()
        
        # ✅ Users can only update their own profile
        if not request.user.is_staff and request.user.id != instance.id:
            return Response(
                {'error': 'Permission denied'},
                status=403
            )
        
        return super().update(request, *args, **kwargs)
```

## Complete Application Examples

### Example 6: Banking API

```python
from decimal import Decimal
from marshmallow import Schema, fields, validates, ValidationError

# Models
class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    account_number = db.Column(db.String(20))
    balance = db.Column(db.Numeric(12, 2))
    account_type = db.Column(db.String(50))
    is_active = db.Column(db.Boolean)
    overdraft_limit = db.Column(db.Numeric(10, 2))
    interest_rate = db.Column(db.Numeric(5, 2))
    internal_score = db.Column(db.Integer)  # Credit score

# ✅ SECURE Schemas
class AccountPublicSchema(Schema):
    """Customer view - safe fields only"""
    id = fields.Int(dump_only=True)
    account_number = fields.Str()
    balance = fields.Decimal(as_string=True)
    account_type = fields.Str()
    is_active = fields.Bool()
    # ✅ overdraft_limit hidden
    # ✅ interest_rate hidden
    # ✅ internal_score hidden

class AccountAdminSchema(AccountPublicSchema):
    """Bank employee view"""
    overdraft_limit = fields.Decimal(as_string=True)
    interest_rate = fields.Decimal(as_string=True)
    internal_score = fields.Int()
    user_id = fields.Int()

class TransactionRequestSchema(Schema):
    """Transaction creation - no amount manipulation"""
    recipient_account = fields.Str(required=True)
    amount = fields.Decimal(required=True, places=2)
    description = fields.Str()
    
    @validates('amount')
    def validate_amount(self, value):
        if value <= 0:
            raise ValidationError('Amount must be positive')
        if value > Decimal('10000'):
            raise ValidationError('Amount exceeds single transaction limit')

# ✅ SECURE Endpoints
@app.route('/api/accounts/<int:account_id>')
@require_auth
def get_account(account_id):
    account = Account.query.get_or_404(account_id)
    
    # ✅ Authorization: user owns account or is admin
    if account.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    # ✅ Different view for admins
    if current_user.is_admin:
        schema = AccountAdminSchema()
    else:
        schema = AccountPublicSchema()
    
    return jsonify(schema.dump(account))

@app.route('/api/transactions', methods=['POST'])
@require_auth
def create_transaction():
    schema = TransactionRequestSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400
    
    # ✅ Server validates and processes transaction
    sender_account = Account.query.filter_by(
        user_id=current_user.id
    ).first()
    
    if not sender_account:
        return jsonify({'error': 'No account found'}), 404
    
    # ✅ Server-side balance check
    if sender_account.balance < data['amount']:
        return jsonify({'error': 'Insufficient funds'}), 400
    
    # ✅ Server controls balance changes
    sender_account.balance -= data['amount']
    
    recipient = Account.query.filter_by(
        account_number=data['recipient_account']
    ).first()
    
    if recipient:
        recipient.balance += data['amount']
    
    # Create transaction record
    transaction = Transaction(
        sender_id=sender_account.id,
        recipient_id=recipient.id if recipient else None,
        amount=data['amount'],
        description=data.get('description', ''),
        status='completed',  # ✅ Server-set
        created_at=datetime.utcnow()  # ✅ Server-set
    )
    
    db.session.add(transaction)
    db.session.commit()
    
    return jsonify({
        'transaction_id': transaction.id,
        'status': 'completed',
        'new_balance': str(sender_account.balance)
    }), 201
```

## What's Next?

- **[Lab](./lab/api03-mass-assignment-lab/)**: Practice exploiting and fixing these vulnerabilities in a hands-on environment
- **[Prevention](./prevention.md)**: Review best practices for preventing property-level authorization issues
- **[Attack Vectors](./attack-vectors.md)**: Study how attackers exploit these flaws

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
